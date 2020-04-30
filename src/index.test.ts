import * as jwebtgcp from '.';
import { prepareSignOptions } from '.';

describe('jwebtgcp', () => {
  it('should export prepareSignOptions function', () => {
    expect.assertions(1);

    expect(typeof prepareSignOptions).toBe('function');
  });

  it('should not export additional functions', () => {
    expect.assertions(1);

    expect(Object.keys(jwebtgcp)).toStrictEqual(['prepareSignOptions']);
  });
});
