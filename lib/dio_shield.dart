/// Dio Shield — PII-sanitized HTTP logging interceptor for Dio.
///
/// **Requires** the `dio` package in your pubspec.yaml:
///
/// ```yaml
/// dependencies:
///   dio: ^5.0.0
/// ```
///
/// ```dart
/// import 'package:flutter_neo_shield/dio_shield.dart';
///
/// final dio = Dio();
/// dio.interceptors.add(DioShieldInterceptor());
/// ```
library dio_shield;

export 'src/log_shield/dio_shield_interceptor.dart';
