-- lib.lua is put before the source of every script (see scripts.go): the
-- functions they share. Every key a script touches is in KEYS, named by the
-- caller.
--
-- Tokens. Every folder has two random tokens, one for the listings (tl:)
-- and one for the entries (te:). A value records the tokens of every folder
-- from the root down to its own, as they were when it was written; it is
-- served only while each of them is still the one recorded. Replacing the
-- token of a folder (DeleteSubtree, DeleteEntriesBelow) invalidates every
-- value below it in one command, and a token evicted or expired does the
-- same: an absent key never means "unchanged".
--
-- Generations. g: holds a random number, drawn by the caller when the key
-- is created, and INCR by every write that bumps it. What a caller is given
-- is that number plus a fingerprint of the listing tokens of the folder and
-- of its ancestors: it moves with a write to the listing, with a
-- DeleteSubtree above it, and with the eviction of either key (a new random
-- number, a new token). The number is below 2^52 and the fingerprint too:
-- their sum is exact in a Lua number (2^53).

local MAX_GENERATION = 4503599627370496 -- 2^52

-- extend gives key the lifetime life (ms) when it has none, and lengthens
-- it otherwise: never shortened, since instances may hold values longer than
-- this one.
local function extend(key, life)
  redis.call('PEXPIRE', key, life, 'NX')
  redis.call('PEXPIRE', key, life, 'GT')
end

-- settle sets each token KEYS[first..last] that is absent to candidate,
-- lengthens its lifetime to life, and returns the tokens joined by ",",
-- root first.
local function settle(first, last, candidate, life)
  local t = {}
  for i = first, last do
    redis.call('SET', KEYS[i], candidate, 'NX')
    extend(KEYS[i], life)
    t[#t + 1] = redis.call('GET', KEYS[i])
  end
  return table.concat(t, ',')
end

-- generation_number reads the raw value of a generation key; anything this
-- format does not write is an error, never a generation.
local function generation_number(raw)
  local n = tonumber(raw)
  if not n or n < 1 or n >= MAX_GENERATION or n ~= math.floor(n) then
    error('redisstore: not a generation of this format')
  end
  return n
end

-- current is the generation a caller is given, as a decimal string, nil
-- when the generation key is absent. tokens is what settle returned.
local function current(gkey, tokens)
  local raw = redis.call('GET', gkey)
  if not raw then
    return nil
  end
  -- 52 bits in two parts: tonumber(s, 16) goes through strtoul, which a
  -- 32-bit build of Redis would saturate on 13 hex digits.
  local h = redis.sha1hex(tokens)
  local fp = tonumber(string.sub(h, 1, 6), 16) * 268435456 + tonumber(string.sub(h, 7, 13), 16)
  return string.format('%.0f', generation_number(raw) + fp)
end

-- bump moves a generation: INCR when it exists, the random start drawn by
-- the caller when it does not.
local function bump(gkey, start, life)
  local raw = redis.call('GET', gkey)
  if raw then
    generation_number(raw)
    redis.call('INCR', gkey)
  else
    redis.call('SET', gkey, start)
  end
  extend(gkey, life)
end

-- held tells whether the hash at key is a listing this client reads: its
-- reserved field "m" reads "<version>:<lifetime>" and its field "t" holds
-- the tokens of now.
local function held(key, version, tokens)
  local f = redis.call('HMGET', key, 'm', 't')
  local life = string.match(f[1] or '', '^' .. version .. ':(%d+)$')
  return life ~= nil and tonumber(life) > 0 and f[2] == tokens
end

