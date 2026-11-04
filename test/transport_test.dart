// HttpTransport: every call that got no answer is an ApiException, the one
// failure an app handles.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:necessary/necessary.dart';

HttpTransport _failing(Object failure) => HttpTransport(
  'https://backend.example',
  client: MockClient((http.Request request) async => throw failure),
);

void main() {
  test(
    'a refused certificate is an ApiException, not a raw TLS error',
    () async {
      await expectLater(
        _failing(
          const HandshakeException('CERTIFICATE_VERIFY_FAILED'),
        ).send('POST', '/v1/installations/register'),
        throwsA(isA<ApiException>()),
      );
    },
  );

  test('so are a socket and a client failure', () async {
    await expectLater(
      _failing(
        const SocketException('refused'),
      ).send('POST', '/v1/installations/register'),
      throwsA(isA<ApiException>()),
    );
    await expectLater(
      _failing(
        http.ClientException('closed'),
      ).send('POST', '/v1/installations/register'),
      throwsA(isA<ApiException>()),
    );
  });
}
