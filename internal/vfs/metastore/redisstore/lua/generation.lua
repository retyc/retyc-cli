-- Generation: the generation of a listing, created when absent.
--
-- KEYS[1]     generation of the listing
-- KEYS[2..]   listing token of each folder, root first, the folder last
-- ARGV[1]     candidate token, for the tokens that are absent
-- ARGV[2]     lifetime of a token, in milliseconds
-- ARGV[3]     random start of a generation that is absent
-- ARGV[4]     lifetime of a generation, in milliseconds
--
-- Returns the generation as a decimal string. The tokens are settled first:
-- a write that later finds one of them replaced is refused.
local tokens = settle(2, #KEYS, ARGV[1], ARGV[2])
redis.call('SET', KEYS[1], ARGV[3], 'NX')
-- Read, and so checked, before it is extended: a value this format does not
-- write fails here and is left to expire, not kept alive by every call.
local gen = current(KEYS[1], tokens)
extend(KEYS[1], ARGV[4])
return gen
