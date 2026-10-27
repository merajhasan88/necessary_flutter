/// How the plugin's messages reach your backend: by default over HTTPS, under
/// the base URL your app sets (the public guide, section 4).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'errors.dart';

/// Sends one request to your backend and answers its JSON object. A refusal
/// is thrown as an [ApiException] with the backend's `code`, `message` and
/// `details` (the public guide, section 4, Errors).
abstract class DeviceTrustTransport {
  /// [encodedBody] is sent exactly as given: it is what a request proof
  /// hashes. A GET sends no body.
  Future<Map<String, dynamic>> send(
    String method,
    String path, {
    String? encodedBody,
    String? bearerToken,
    Map<String, String> headers = const <String, String>{},
  });

  void close();
}

/// JSON over HTTPS under [baseUrl]. A release build refuses any other
/// scheme, so a mistyped endpoint fails loudly instead of sending tokens in
/// the clear.
class HttpTransport implements DeviceTrustTransport {
  HttpTransport(
    this.baseUrl, {
    http.Client? client,
    this.timeout = const Duration(seconds: 15),
  }) : _client = client ?? http.Client();

  final String baseUrl;
  final Duration timeout;
  final http.Client _client;

  String get _base {
    if (baseUrl.isEmpty) {
      throw ApiException(
        'No API base URL was set for the backend.',
        code: 'api_base_url_missing',
      );
    }
    if (kReleaseMode && !baseUrl.toLowerCase().startsWith('https://')) {
      throw ApiException(
        'The API base URL must be an https:// URL in a release build.',
        code: 'api_base_url_insecure',
      );
    }
    return baseUrl.endsWith('/')
        ? baseUrl.substring(0, baseUrl.length - 1)
        : baseUrl;
  }

  @override
  Future<Map<String, dynamic>> send(
    String method,
    String path, {
    String? encodedBody,
    String? bearerToken,
    Map<String, String> headers = const <String, String>{},
  }) async {
    final http.Request request = http.Request(method, Uri.parse('$_base$path'))
      ..headers.addAll(<String, String>{
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        if (bearerToken != null) 'Authorization': 'Bearer $bearerToken',
        ...headers,
      });
    if (method != 'GET') {
      request.body = encodedBody ?? '{}';
    }

    late final http.Response response;
    try {
      response = await _client
          .send(request)
          .then(http.Response.fromStream)
          .timeout(timeout);
    } on TimeoutException {
      throw ApiException('The server did not respond before the timeout.');
    } on SocketException catch (error) {
      throw ApiException('Network connection failed: ${error.message}');
    } on http.ClientException catch (error) {
      throw ApiException('HTTP connection failed: ${error.message}');
    }

    Map<String, dynamic> decoded = <String, dynamic>{};
    if (response.body.trim().isNotEmpty) {
      try {
        decoded = Map<String, dynamic>.from(jsonDecode(response.body) as Map);
      } catch (_) {
        throw ApiException(
          'The server returned a non-JSON response.',
          statusCode: response.statusCode,
        );
      }
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final Object? error = decoded['error'];
      final Map<String, dynamic>? refusal = error is Map
          ? Map<String, dynamic>.from(error)
          : null;
      final Object? details = refusal?['details'];
      throw ApiException(
        refusal?['message'] as String? ??
            'The server rejected the request (${response.statusCode}).',
        statusCode: response.statusCode,
        code: refusal?['code'] as String?,
        details: details is Map ? Map<String, dynamic>.from(details) : null,
      );
    }
    return decoded;
  }

  @override
  void close() => _client.close();
}
