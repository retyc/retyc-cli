-- DeleteListing: removes a listing and bumps its generation.
--
-- KEYS[1]     listing
-- KEYS[2]     generation of the listing
-- KEYS[3..]   listing token of each folder, root first, the folder last
-- ARGV[1]     lifetime of a generation, in milliseconds
-- ARGV[2]     lifetime of a token, in milliseconds
-- ARGV[3]     candidate token
-- ARGV[4]     random start of a generation
--
-- Returns the new generation as a decimal string.
local tokens = settle(3, #KEYS, ARGV[3], ARGV[2])
redis.call('UNLINK', KEYS[1])
bump(KEYS[2], ARGV[4], ARGV[1])
return current(KEYS[2], tokens)
