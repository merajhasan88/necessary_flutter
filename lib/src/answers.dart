/// Reading what your backend answered.
library;

import 'errors.dart';

/// The text [field] of a [answer] your backend gave. A field it left out is
/// an [ApiException], as every failure of a call is, never a cast error.
String answerText(Map<String, dynamic> answer, String field) {
  final Object? value = answer[field];
  if (value is String && value.isNotEmpty) {
    return value;
  }
  throw ApiException(
    'The backend answered no $field.',
    code: 'invalid_backend_answer',
  );
}
