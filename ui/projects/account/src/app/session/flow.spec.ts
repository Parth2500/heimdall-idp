import { requestIdOrNull, resumePath } from './flow';

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
