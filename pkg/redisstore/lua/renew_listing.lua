-- RenewListingIf: gives a listing that is held its full lifetime again and a
-- new ETag, its children untouched, and bumps its generation, when the
-- generation is still the one expected.
--
-- KEYS[1]     listing
-- KEYS[2]     generation of the listing
-- KEYS[3..]   listing token of each folder, root first, the folder last
-- ARGV[1]     generation expected, as a decimal string
-- ARGV[2]     lifetime left to the listing, in milliseconds
-- ARGV[3]     lifetime of a generation, in milliseconds
-- ARGV[4]     lifetime of a token, in milliseconds
-- ARGV[5]     candidate token
-- ARGV[6]     random start of a generation
-- ARGV[7]     version of the values this client reads
-- ARGV[8]     reserved field "m" to write: "<version>:<full lifetime>"
-- ARGV[9]     ETag, "" for none
--
-- Returns 1 when the listing was renewed, 0 when the generation moved or no
-- listing this version reads is held under the tokens of now: nothing is
-- then written, the generation included, and the caller puts the listing
-- under the same generation. A listing written before a DeleteSubtree above
-- it is never renewed: it would come back.
local tokens = settle(3, #KEYS, ARGV[5], ARGV[4])
if current(KEYS[2], tokens) ~= ARGV[1] then
  return 0
end
if not held(KEYS[1], ARGV[7], tokens) then
  return 0
end
redis.call('HSET', KEYS[1], 'm', ARGV[8])
if ARGV[9] ~= '' then
  redis.call('HSET', KEYS[1], 'etag', ARGV[9])
else
  redis.call('HDEL', KEYS[1], 'etag')
end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
bump(KEYS[2], ARGV[6], ARGV[3])
return 1
