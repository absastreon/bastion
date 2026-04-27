import { describe, it, expect } from 'vitest';
import { VERSION } from '../src/index.js';

describe('bastion-shared', () => {
  it('exports VERSION', () => {
    expect(VERSION).toBe('0.1.3');
  });
});
