-- RemoveNode: drops one child of a listing that is held, and bumps the
-- generation whether or not one is. See upsert_node.lua.
--
-- KEYS[1]     listing
-- KEYS[2]     generation of the listing
-- KEYS[3..]   listing token of each folder, root first, the folder last
-- ARGV[1]     lifetime of a generation, in milliseconds
-- ARGV[2]     lifetime of a token, in milliseconds
-- ARGV[3]     candidate token
-- ARGV[4]     random start of a generation
-- ARGV[5]     version of the values this client reads
-- ARGV[6]     field of the child
--
-- Returns the new generation as a decimal string.
local tokens = settle(3, #KEYS, ARGV[3], ARGV[2])
if held(KEYS[1], ARGV[5], tokens) then
  redis.call('HDEL', KEYS[1], ARGV[6], 'etag')
else
  redis.call('UNLINK', KEYS[1])
end
bump(KEYS[2], ARGV[4], ARGV[1])
return current(KEYS[2], tokens)
