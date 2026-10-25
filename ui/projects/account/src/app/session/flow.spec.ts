import { isSafeDestination, logoutRequestOrNull, requestIdOrNull, resumePath } from './flow';

describe('requestIdOrNull', () => {
  it('accepts a UUID and lowercases it', () => {
    expect(requestIdOrNull('0192D7C3-0000-7000-8000-000000000001')).toBe(
      '0192d7c3-0000-7000-8000-000000000001',
    );
  });

  it.each([null, '', 'abc', 'https://evil.example', '0192d7c3-0000-7000-8000-00000000000Z'])(
    'refuses %s',
    (value) => {
      expect(requestIdOrNull(value)).toBeNull();
    },
  );
});

describe('resumePath', () => {
  it('is the fixed relative resume path', () => {
    expect(resumePath('0192d7c3-0000-7000-8000-000000000001')).toBe(
      '/oauth/v1/authorize/resume?request_id=0192d7c3-0000-7000-8000-000000000001',
    );
  });
});

describe('logoutRequestOrNull', () => {
  it('keeps URL-safe text unchanged', () => {
    expect(logoutRequestOrNull('CfDJ8Abc_def-123')).toBe('CfDJ8Abc_def-123');
  });

  it.each([null, '', 'https://evil.example/', 'a b', 'a+b/c=', 'A'.repeat(4097)])(
    'refuses %s',
    (value) => {
      expect(logoutRequestOrNull(value)).toBeNull();
    },
  );
});

describe('isSafeDestination', () => {
  it.each([
    'https://app.example.com/bye?state=1',
    'http://localhost:4200/login',
    '/account/signed-out?logout=done',
  ])('allows %s', (value) => {
    expect(isSafeDestination(value)).toBe(true);
  });

  it.each([
    'javascript:alert(1)',
    'data:text/html,x',
    '//evil.example/',
    '/\\evil.example/',
    'evil.example',
    '',
    null,
    42,
  ])('refuses %s', (value) => {
    expect(isSafeDestination(value)).toBe(false);
  });
});
