import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() {
    PIIDetector().reset();
  });

  group('JsonSanitizer', () {
    group('Flat JSON with sensitive keys', () {
      test('redacts name, email, and password', () {
        final result = JsonSanitizer.sanitize({
          'name': 'John Doe',
          'email': 'john@example.com',
          'password': 'secret123',
        });
        expect(result['name'], '[REDACTED]');
        expect(result['email'], '[REDACTED]');
        expect(result['password'], '[REDACTED]');
      });

      test('redacts token and ssn keys', () {
        final result = JsonSanitizer.sanitize({
          'token': 'abc123',
          'ssn': '123-45-6789',
        });
        expect(result['token'], '[REDACTED]');
        expect(result['ssn'], '[REDACTED]');
      });
    });

    group('Non-sensitive keys pass through', () {
      test('preserves non-sensitive string values', () {
        final result = JsonSanitizer.sanitize({
          'id': 123,
          'status': 'active',
          'count': 42,
        });
        expect(result['id'], 123);
        expect(result['status'], 'active');
        expect(result['count'], 42);
      });

      test('preserves boolean and null values', () {
        final result = JsonSanitizer.sanitize({
          'active': true,
          'deleted': false,
          'metadata': null,
        });
        expect(result['active'], isTrue);
        expect(result['deleted'], isFalse);
        expect(result['metadata'], isNull);
      });
    });

    group('Nested JSON', () {
      test('sanitizes sensitive keys inside nested maps', () {
        final result = JsonSanitizer.sanitize({
          'user': {
            'name': 'Jane',
            'email': 'jane@test.com',
            'id': 99,
          },
        });
        final user = result['user'] as Map<String, dynamic>;
        expect(user['name'], '[REDACTED]');
        expect(user['email'], '[REDACTED]');
        expect(user['id'], 99);
      });

      test('sanitizes deeply nested structures', () {
        final result = JsonSanitizer.sanitize({
          'data': {
            'profile': {
              'name': 'Deep User',
              'role': 'admin',
            },
          },
        });
        final profile = (result['data'] as Map<String, dynamic>)['profile']
            as Map<String, dynamic>;
        expect(profile['name'], '[REDACTED]');
        expect(profile['role'], 'admin');
      });
    });

    group('List of maps', () {
      test('sanitizes each map in a list', () {
        final result = JsonSanitizer.sanitize({
          'users': [
            {'name': 'Alice', 'id': 1},
            {'name': 'Bob', 'id': 2},
          ],
        });
        final users = result['users'] as List<dynamic>;
        expect(users, hasLength(2));
        expect((users[0] as Map<String, dynamic>)['name'], '[REDACTED]');
        expect((users[0] as Map<String, dynamic>)['id'], 1);
        expect((users[1] as Map<String, dynamic>)['name'], '[REDACTED]');
        expect((users[1] as Map<String, dynamic>)['id'], 2);
      });
    });

    group('PII in non-sensitive values', () {
      test('detects phone number in non-sensitive key value', () {
        final result = JsonSanitizer.sanitize({
          'note': 'Call 555-123-4567',
        });
        expect(result['note'], contains('[PHONE HIDDEN]'));
        expect(result['note'], isNot(contains('555-123-4567')));
      });

      test('detects email in non-sensitive key value', () {
        final result = JsonSanitizer.sanitize({
          'message': 'Contact alice@example.com for details',
        });
        expect(result['message'], contains('[EMAIL HIDDEN]'));
        expect(result['message'], isNot(contains('alice@example.com')));
      });

      test('detects IP address in non-sensitive key value', () {
        final result = JsonSanitizer.sanitize({
          'log': 'Request from 192.168.1.100',
        });
        expect(result['log'], contains('[IP HIDDEN]'));
      });
    });

    group('Empty map', () {
      test('returns empty map for empty input', () {
        final result = JsonSanitizer.sanitize({});
        expect(result, isEmpty);
      });
    });

    group('Custom sensitive keys', () {
      test('uses custom sensitive keys list', () {
        final result = JsonSanitizer.sanitize(
          {
            'customField': 'should be redacted',
            'name': 'should pass through',
            'normalField': 'safe data',
          },
          sensitiveKeys: ['customField'],
        );
        expect(result['customField'], '[REDACTED]');
        expect(result['name'], 'should pass through');
        expect(result['normalField'], 'safe data');
      });

      test('custom sensitive keys are case-insensitive', () {
        final result = JsonSanitizer.sanitize(
          {
            'MySecret': 'top secret',
          },
          sensitiveKeys: ['mysecret'],
        );
        expect(result['MySecret'], '[REDACTED]');
      });
    });
  });
}
