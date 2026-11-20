-- PutListing / PutListingIf: replaces a listing and bumps its generation,
-- when the generation is still the one expected.
--
-- KEYS[1]     listing
-- KEYS[2]     generation of the listing
-- KEYS[3..]   listing token of each folder, root first, the folder last
-- ARGV[1]     generation expected, as a decimal string; "" writes whatever
--             the generation is
-- ARGV[2]     lifetime of the listing, in milliseconds
-- ARGV[3]     lifetime of a generation, in milliseconds
-- ARGV[4]     lifetime of a token, in milliseconds
-- ARGV[5]     candidate token
-- ARGV[6]     random start of a generation
-- ARGV[7..]   field, value, ... of the listing; none removes the one held
--
-- Returns 1 when the generation matched (the listing held is replaced, or
-- removed), 0 when it did not (nothing is written). An absent generation
-- never matches: it was evicted since it was read.
local tokens = settle(3, #KEYS, ARGV[5], ARGV[4])
if ARGV[1] ~= '' and current(KEYS[2], tokens) ~= ARGV[1] then
  return 0
end
redis.call('UNLINK', KEYS[1])
local last = #ARGV
if last > 6 then
  -- unpack is bounded by the Lua stack: 512 fields a call.
  local i = 7
  while i <= last do
    local j = math.min(i + 1023, last)
    redis.call('HSET', KEYS[1], unpack(ARGV, i, j))
    i = j + 1
  end
  redis.call('HSET', KEYS[1], 't', tokens)
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
bump(KEYS[2], ARGV[6], ARGV[3])
return 1
