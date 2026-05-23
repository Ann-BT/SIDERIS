'use strict';

const THREAT_LEVELS = {
  allow: 0,
  rate_limit: 1,
  captcha: 2,
  soft_block: 3,
  hard_block: 4
};

const ACTION_WEIGHTS = {
  'block':      3,
  'challenge':  2,
  'rate_limit': 1
};

module.exports = { THREAT_LEVELS, ACTION_WEIGHTS };
