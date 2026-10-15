-- PutEntry / PutEntryIf: stores one entry of a folder, when the generation
-- of the folder's listing is still the one expected. The generation is not
-- bumped.
--
-- KEYS[1]          entries of the folder
-- KEYS[2]          generation of the folder's listing
-- KEYS[3..2+n]     listing token of each folder, root first, the folder last
-- KEYS[3+n..2+2n]  entry token of each folder, in the same order
-- ARGV[1]          generation expected, as a decimal string; "" writes
--                  whatever the generation is
-- ARGV[2]          field of the entry
-- ARGV[3]          value of the entry
-- ARGV[4]          lifetime of the field, in milliseconds; "0" for an entry
--                  that is not stored: the field is removed
-- ARGV[5]          lifetime of a token, in milliseconds
-- ARGV[6]          candidate token
-- ARGV[7]          n, the number of folders from the root to this one
--
-- Returns 1 when the generation matched, 0 when it did not (nothing is
-- written; an absent generation never matches).
--
-- The hash records the entry tokens in its field "t". One that records
-- other tokens holds entries a DeleteEntriesBelow (or an eviction) made
-- stale: it is emptied before the write. "t" is only written to a new hash
-- (HSET clears the lifetime of a field), and lives as long as the longest
-- entry written under it.
local n = tonumber(ARGV[7])
if ARGV[1] ~= '' then
  local listing = settle(3, 2 + n, ARGV[6], ARGV[5])
  if current(KEYS[2], listing) ~= ARGV[1] then
    return 0
  end
end
local tokens = settle(3 + n, 2 + 2 * n, ARGV[6], ARGV[5])
if redis.call('HGET', KEYS[1], 't') ~= tokens then
  redis.call('UNLINK', KEYS[1])
end
if ARGV[4] == '0' then
  redis.call('HDEL', KEYS[1], ARGV[2])
  return 1
end
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('HSET', KEYS[1], 't', tokens)
end
redis.call('HSET', KEYS[1], ARGV[2], ARGV[3])
redis.call('HPEXPIRE', KEYS[1], ARGV[4], 'FIELDS', 1, ARGV[2])
redis.call('HPEXPIRE', KEYS[1], ARGV[4], 'NX', 'FIELDS', 1, 't')
redis.call('HPEXPIRE', KEYS[1], ARGV[4], 'GT', 'FIELDS', 1, 't')
return 1
