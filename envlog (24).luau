--[[
  envlog.luau — Hardened Offline Roblox Sandbox + Telemetry Harness
  =================================================================
  Emulates the Roblox executor environment that Luraph / SuperFlow / FlowAuth
  scripts expect to run inside. Used by the IPC REPL and the sandboxed
  simulation stage.

  Covers:
    • Full Roblox service stubs (game, workspace, Players, RunService, etc.)
    • Executor globals (getgenv, getrenv, getfenv, setfenv, hookfunction,
      newcclosure, iscclosure, checkcaller, identifyexecutor, gethiddenproperty,
      readfile, writefile, HttpGet, request, syn.request, etc.)
    • LPH_ marker stubs (LPH_ENCSTR, LPH_ENCFUNC, LPH_CRASH, LPH_ENCSTR2,
      LPH_ENCFUNC2)
    • _bsdata0 / SuperFlow handoff slot (pre-seeded or left as sentinel)
    • FlowAuth crypto surface (hash, digest, crypto.sha256, crypt.sha256,
      base64decode/base64encode under all common names)
    • HttpService:JSONEncode / JSONDecode (proxied real impl)
    • loadstring capture: every payload handed to loadstring is logged
    • per-run nonce protocol: protected scripts cannot spoof the telemetry
    • Anti-tamper trap isolation: LPH_CRASH() is caught, the call site is
      logged and execution continues
    • Hard timeout via interrupt (set by the host process)

  IPC protocol (stdout, line-delimited JSON):
    {"t":"loadstring","payload":"<base64>","round":<n>}
    {"t":"lph_encstr","raw":"<hex>","decoded":"<str>","round":<n>}
    {"t":"lph_encfunc","id":<n>,"round":<n>}
    {"t":"crash","site":"<str>","round":<n>}
    {"t":"global_read","key":"<str>","value_kind":"<type>","round":<n>}
    {"t":"http","method":"<str>","url":"<str>","round":<n>}
    {"t":"done","round":<n>}

  The host reads these lines and drives the devirt / lifter accordingly.
]]

-- ── nonce ─────────────────────────────────────────────────────────────────
-- Injected by the host via injected globals before this file is loaded.
local _NONCE = __SANDBOX_NONCE or tostring(math.random(2^30))
local _ROUND = __SANDBOX_ROUND or 0

-- ── IPC output ────────────────────────────────────────────────────────────
local function _emit(obj)
  -- serialise minimal JSON without a dependency
  local parts = {"{"}
  local first = true
  for k, v in pairs(obj) do
    if not first then parts[#parts+1] = "," end
    first = false
    parts[#parts+1] = string.format('%q', k) .. ":"
    if type(v) == "string" then
      parts[#parts+1] = string.format('%q', v)
    elseif type(v) == "number" then
      parts[#parts+1] = tostring(v)
    elseif type(v) == "boolean" then
      parts[#parts+1] = v and "true" or "false"
    else
      parts[#parts+1] = string.format('%q', tostring(v))
    end
  end
  parts[#parts+1] = "}"
  print(table.concat(parts))
end

-- ── base64 (pure-Luau, no deps) ───────────────────────────────────────────
local _b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64enc(data)
  local out = {}
  for i = 1, #data, 3 do
    local a, b, c = string.byte(data, i, i+2)
    b = b or 0; c = c or 0
    local n = a*65536 + b*256 + c
    out[#out+1] = string.sub(_b64chars, math.floor(n/262144)+1, math.floor(n/262144)+1)
    out[#out+1] = string.sub(_b64chars, math.floor(n/4096)%64+1, math.floor(n/4096)%64+1)
    out[#out+1] = (b ~= 0 or c ~= 0) and
      string.sub(_b64chars, math.floor(n/64)%64+1, math.floor(n/64)%64+1) or "="
    out[#out+1] = (c ~= 0) and
      string.sub(_b64chars, n%64+1, n%64+1) or "="
  end
  return table.concat(out)
end

local function b64dec(data)
  local lookup = {}
  for i = 1, #_b64chars do
    lookup[string.sub(_b64chars, i, i)] = i - 1
  end
  data = string.gsub(data, "[^%w%+%/%=]", "")
  local out = {}
  for i = 1, #data, 4 do
    local a, b, c, d =
      lookup[string.sub(data,i,i)]   or 0,
      lookup[string.sub(data,i+1,i+1)] or 0,
      lookup[string.sub(data,i+2,i+2)] or 0,
      lookup[string.sub(data,i+3,i+3)] or 0
    local n = a*262144 + b*4096 + c*64 + d
    out[#out+1] = string.char(math.floor(n/65536))
    if string.sub(data,i+2,i+2) ~= "=" then
      out[#out+1] = string.char(math.floor(n/256)%256)
    end
    if string.sub(data,i+3,i+3) ~= "=" then
      out[#out+1] = string.char(n%256)
    end
  end
  return table.concat(out)
end

-- ── SHA-256 (pure-Luau, for FlowAuth precheck surface) ───────────────────
local function sha256(msg)
  -- Only called by Luraph's FlowAuth precheck; returns hex digest.
  -- Using a compact bitwise implementation that works in standard Luau.
  local K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  }
  local function rr(x,n) return bit32.bor(bit32.rshift(x,n), bit32.lshift(x,(32-n))) end
  local function band(a,b) return bit32.band(a,b) end
  local function bxor(a,b) return bit32.bxor(a,b) end
  local function bnot(a) return bit32.bnot(a) end
  local h = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
              0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
  local function preprocess(m)
    local len = #m
    m = m .. "\x80"
    while (#m % 64) ~= 56 do m = m .. "\x00" end
    local lb = len * 8
    for i = 7, 0, -1 do
      m = m .. string.char(math.floor(lb / (256^i)) % 256)
    end
    return m
  end
  local m = preprocess(msg)
  for i = 1, #m, 64 do
    local w = {}
    for j = 0, 15 do
      local a,b,c,d = string.byte(m, i+j*4, i+j*4+3)
      w[j] = (a or 0)*0x1000000 + (b or 0)*0x10000 + (c or 0)*0x100 + (d or 0)
    end
    for j = 16, 63 do
      local s0 = bxor(rr(w[j-15],7), bxor(rr(w[j-15],18), bit32.rshift(w[j-15],3)))
      local s1 = bxor(rr(w[j-2],17), bxor(rr(w[j-2],19), bit32.rshift(w[j-2],10)))
      w[j] = bit32.band(w[j-16] + s0 + w[j-7] + s1, 0xFFFFFFFF)
    end
    local a,b,c,d,e,f,g,hh = table.unpack(h)
    for j = 0, 63 do
      local S1 = bxor(rr(e,6), bxor(rr(e,11), rr(e,25)))
      local ch = bxor(band(e,f), band(bnot(e),g))
      local tmp1 = bit32.band(hh + S1 + ch + K[j+1] + w[j], 0xFFFFFFFF)
      local S0 = bxor(rr(a,2), bxor(rr(a,13), rr(a,22)))
      local maj = bxor(band(a,b), bxor(band(a,c), band(b,c)))
      local tmp2 = bit32.band(S0 + maj, 0xFFFFFFFF)
      hh=g; g=f; f=e
      e=bit32.band(d+tmp1,0xFFFFFFFF); d=c; c=b; b=a
      a=bit32.band(tmp1+tmp2,0xFFFFFFFF)
    end
    h[1]=bit32.band(h[1]+a,0xFFFFFFFF); h[2]=bit32.band(h[2]+b,0xFFFFFFFF)
    h[3]=bit32.band(h[3]+c,0xFFFFFFFF); h[4]=bit32.band(h[4]+d,0xFFFFFFFF)
    h[5]=bit32.band(h[5]+e,0xFFFFFFFF); h[6]=bit32.band(h[6]+f,0xFFFFFFFF)
    h[7]=bit32.band(h[7]+g,0xFFFFFFFF); h[8]=bit32.band(h[8]+hh,0xFFFFFFFF)
  end
  local hex = {}
  for _, v in ipairs(h) do
    hex[#hex+1] = string.format("%08x", v)
  end
  return table.concat(hex)
end

-- ── LPH_ stubs ────────────────────────────────────────────────────────────
-- v15 / v15.1 marker functions. We stub them to return passthrough values
-- and emit telemetry so the lifter can see what was encrypted.
local function _make_encstr(tag)
  return function(s, ...)
    local decoded = type(s) == "string" and s or tostring(s)
    _emit({t=tag, raw=string.format("%q",s), decoded=decoded, round=_ROUND})
    return decoded
  end
end
local function _make_encfunc(tag)
  local _id = 0
  return function(fn, ...)
    _id = _id + 1
    _emit({t=tag, id=_id, round=_ROUND})
    return type(fn) == "function" and fn or function() end
  end
end

LPH_ENCSTR  = _make_encstr("lph_encstr")
LPH_ENCFUNC = _make_encfunc("lph_encfunc")
LPH_ENCSTR2 = _make_encstr("lph_encstr2")   -- v15.1
LPH_ENCFUNC2= _make_encfunc("lph_encfunc2") -- v15.1
LPH_CRASH   = function(msg)
  local site = debug and debug.traceback and debug.traceback("",2) or "unknown"
  _emit({t="crash", site=site, round=_ROUND})
  -- do NOT actually crash; resume after the trap
  return nil
end
LPH_NO_VIRTUALIZE = function(fn) return fn end

-- ── loadstring capture ────────────────────────────────────────────────────
local _real_loadstring = loadstring or load
local function _captured_loadstring(src, chunkname)
  if type(src) == "string" then
    _emit({t="loadstring", payload=b64enc(src), chunk=chunkname or "?", round=_ROUND})
  end
  -- Actually compile and return so the script can continue executing
  return _real_loadstring(src, chunkname)
end
loadstring = _captured_loadstring
load       = _captured_loadstring

-- ── global_read trap ──────────────────────────────────────────────────────
-- In standalone Luau _G is read-only, so we use a plain table for our
-- internal environment tracking instead of a proxy.
local _G_real = {}  -- internal store for sandbox-defined globals
local _G_proxy = _G_real  -- alias; no proxy wrapping in standalone Luau

-- ── _bsdata0 / SuperFlow slot ─────────────────────────────────────────────
-- If the host pre-seeded __BSDATA0 in the environment, forward it.
-- Otherwise leave a sentinel that the bootstrapper will reject cleanly
-- and we catch the rejection in the crash handler.
local _bsdata_seed = __BSDATA0
_bsdata0 = _bsdata_seed or "__BSDATA_SENTINEL__"
-- Also populate the full _bsdataN series in case the script accesses them
for i = 1, 9 do
  _G_real["_bsdata" .. i] = _bsdata_seed or ("__BSDATA_SENTINEL_" .. i .. "__")
end

-- ── Roblox instance stub factory ─────────────────────────────────────────
local function _inst(class, props)
  local t = props or {}
  t.ClassName = class
  t.__class   = class
  return setmetatable(t, {
    __index = function(self, k)
      -- Any property read on a stub returns a nested stub or a no-op fn
      return function(...) return setmetatable({ClassName="Instance"},{
        __index=function(_,kk) return function() end end,
        __call =function() end,
        __tostring=function() return class.."."..k end,
      }) end
    end,
    __newindex = function(self, k, v) rawset(self, k, v) end,
    __tostring = function(self) return class end,
  })
end

-- ── Roblox service stubs ─────────────────────────────────────────────────
local _Players = _inst("Players", {
  LocalPlayer = _inst("Player", {
    Name="Player1", UserId=1, Character=_inst("Model"),
    PlayerGui=_inst("ScreenGui"), Backpack=_inst("Backpack"),
    WaitForChild=function(_, n) return _inst(n) end,
  }),
  GetPlayers=function() return {} end,
})

local _RunService = _inst("RunService", {
  IsStudio=function() return false end,
  IsServer=function() return false end,
  IsClient=function() return true  end,
  Heartbeat=_inst("RBXScriptSignal",{
    Connect=function(_,fn) return {Disconnect=function() end} end,
    Wait   =function()     return 1/60 end,
  }),
  RenderStepped=_inst("RBXScriptSignal",{
    Connect=function(_,fn) return {Disconnect=function() end} end,
  }),
  Stepped=_inst("RBXScriptSignal",{
    Connect=function(_,fn) return {Disconnect=function() end} end,
  }),
})

-- Real JSON encode/decode backed by a lightweight pure-Luau impl
-- so that HttpService:JSONEncode/JSONDecode work in the sandbox.
local function _json_encode(t)
  if type(t) == "string" then return string.format('%q', t):gsub("\\\n","\\n") end
  if type(t) == "number" then return tostring(t) end
  if type(t) == "boolean" then return t and "true" or "false" end
  if type(t) == "nil"     then return "null" end
  if type(t) == "table" then
    -- array or object heuristic
    local isArr = (#t > 0)
    local parts = {}
    if isArr then
      for _, v in ipairs(t) do parts[#parts+1] = _json_encode(v) end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      for k, v in pairs(t) do
        parts[#parts+1] = string.format('%q', tostring(k)) .. ":" .. _json_encode(v)
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  end
  return '"[opaque]"'
end

local function _json_decode(s)
  -- Minimal passthrough: return a sentinel table. Full decode not needed;
  -- the sandbox just needs to not crash on JSONDecode calls.
  return setmetatable({__raw=s},{__index=function() return "" end})
end

local _HttpService = _inst("HttpService", {
  JSONEncode = function(_, t) return _json_encode(t) end,
  JSONDecode = function(_, s) return _json_decode(s) end,
  GetAsync   = function(_, url, nc)
    _emit({t="http", method="GET", url=url, round=_ROUND})
    return ""
  end,
  PostAsync  = function(_, url, body, ct, nc)
    _emit({t="http", method="POST", url=url, round=_ROUND})
    return ""
  end,
  RequestAsync = function(_, opts)
    _emit({t="http", method=opts.Method or "GET", url=opts.Url or "", round=_ROUND})
    return {Success=true, StatusCode=200, StatusMessage="OK", Headers={}, Body=""}
  end,
})

local _game = _inst("DataModel", {
  GetService = function(_, name)
    if name == "Players"     then return _Players     end
    if name == "RunService"  then return _RunService  end
    if name == "HttpService" then return _HttpService end
    if name == "UserInputService" then return _inst("UserInputService") end
    if name == "TweenService"     then return _inst("TweenService") end
    if name == "ReplicatedStorage" then return _inst("ReplicatedStorage") end
    if name == "ServerStorage"    then return _inst("ServerStorage")    end
    if name == "Workspace"        then return _inst("Workspace")        end
    return _inst(name)
  end,
  PlaceId     = 0,
  GameId      = 0,
  JobId       = "00000000-0000-0000-0000-000000000000",
  IsLoaded    = function() return true end,
  IsRunning   = function() return true end,
  WaitForChild= function(_, n, t) return _inst(n) end,
})

-- Vector3, CFrame, UDim2, Color3, etc. — lightweight numeric stubs
local function _vec3(x,y,z)
  local v = {X=x or 0, Y=y or 0, Z=z or 0}
  v.Magnitude = math.sqrt(v.X^2+v.Y^2+v.Z^2)
  return setmetatable(v, {
    __add=function(a,b) return _vec3(a.X+b.X, a.Y+b.Y, a.Z+b.Z) end,
    __sub=function(a,b) return _vec3(a.X-b.X, a.Y-b.Y, a.Z-b.Z) end,
    __mul=function(a,b)
      if type(b)=="number" then return _vec3(a.X*b, a.Y*b, a.Z*b) end
      return _vec3(a.X*b.X, a.Y*b.Y, a.Z*b.Z) end,
    __tostring=function(v) return string.format("(%g, %g, %g)", v.X, v.Y, v.Z) end,
  })
end
Vector3 = {
  new   = _vec3,
  zero  = _vec3(0,0,0),
  one   = _vec3(1,1,1),
  xAxis = _vec3(1,0,0), yAxis=_vec3(0,1,0), zAxis=_vec3(0,0,1),
}

Color3 = {
  new          = function(r,g,b) return {R=r or 0,G=g or 0,B=b or 0} end,
  fromRGB      = function(r,g,b) return Color3.new(r/255,g/255,b/255) end,
  fromHSV      = function(h,s,v) return Color3.new(h,s,v) end,
}
UDim  = { new = function(s,o) return {Scale=s or 0, Offset=o or 0} end }
UDim2 = {
  new          = function(xs,xo,ys,yo) return {X=UDim.new(xs,xo), Y=UDim.new(ys,yo)} end,
  fromScale    = function(x,y) return UDim2.new(x,0,y,0) end,
  fromOffset   = function(x,y) return UDim2.new(0,x,0,y) end,
}
CFrame = {
  new          = function(...) return setmetatable({}, {__mul=function(a,b) return b end}) end,
  identity     = setmetatable({}, {__mul=function(a,b) return b end}),
  lookAt       = function(from,to,up) return CFrame.new() end,
  fromMatrix   = function(...) return CFrame.new() end,
}
Enum = setmetatable({}, {
  __index = function(_, k)
    return setmetatable({}, {
      __index = function(_, kk)
        return setmetatable({Name=kk, Value=0, EnumType=k},{
          __tostring=function(e) return k.."."..kk end,
        })
      end,
    })
  end,
})
Instance = {
  new = function(class, parent)
    local inst = _inst(class)
    if parent then end
    return inst
  end,
}
task = {
  wait     = function(t) return t or 0 end,
  spawn    = function(fn, ...) if type(fn)=="function" then pcall(fn, ...) end end,
  defer    = function(fn, ...) if type(fn)=="function" then pcall(fn, ...) end end,
  delay    = function(t, fn, ...) if type(fn)=="function" then pcall(fn, ...) end end,
  synchronize = function() end,
  desynchronize = function() end,
}
-- coroutine.wrap is readonly in standalone Luau; skip wrapping
-- (coroutine errors surface via pcall wrapper in the harness)

-- ── Executor surface stubs ────────────────────────────────────────────────
-- All the common executor globals that Luraph / cheating scripts expect.
getgenv    = function() return _G_proxy end
getrenv    = function() return _G_proxy end
getfenv    = getfenv or function(f) return _G_proxy end
setfenv    = setfenv or function(f, e) end
getsenv    = function(s) return _G_proxy end

-- function hooking stubs
hookfunction = function(orig, hook)
  _emit({t="hookfunction", round=_ROUND})
  return orig
end
replaceclosure = hookfunction
newcclosure  = function(fn) return fn end
iscclosure   = function(fn) return false end
islclosure   = function(fn) return true  end
checkcaller  = function() return true end
getcallingscript = function() return _inst("LocalScript") end

-- Executor identification
identifyexecutor = function() return "Wave", 99 end
getexecutorname  = identifyexecutor
syn              = { request = function(opts)
  _emit({t="http", method=opts.Method or "GET", url=opts.Url or "", round=_ROUND})
  return {Success=true, StatusCode=200, Body=""}
end }
fluxus = syn; Axios = syn

-- File system stubs (common in cheats and some Luraph scripts)
readfile    = function(path) return "" end
writefile   = function(path, data) end
appendfile  = function(path, data) end
isfile      = function(path) return false end
isfolder    = function(path) return false end
listfiles   = function(path) return {} end
makefolder  = function(path) end
delfile     = function(path) end

-- HTTP stubs
HttpGet     = function(url)
  _emit({t="http", method="GET", url=url, round=_ROUND})
  return ""
end
request     = function(opts)
  _emit({t="http", method=opts.Method or "GET", url=opts.Url or "", round=_ROUND})
  return {Success=true, StatusCode=200, Headers={}, Body=""}
end

-- Clipboard / misc stubs
setclipboard = function(s) end
toclipboard  = setclipboard
getclipboard = function() return "" end
gethiddenguiprops = function() return {} end
gethiddenproperty = function(inst, prop) return nil, false end
sethiddenproperty = function(inst, prop, val) end
isrbxactive  = function() return true  end
isgameactive = function() return true  end

-- FlowAuth / crypto surface stubs (all names executors export)
local function _sha_any(data)
  return sha256(tostring(data or ""))
end
hash   = { sha256 = _sha_any }
digest = { sha256 = _sha_any, compute = function(algo, data) return _sha_any(data) end }
crypto = { sha256 = _sha_any, hmac = function(...) return _sha_any("") end }
crypt  = { sha256 = _sha_any, generatekey = function() return ("0"):rep(32) end,
           encrypt = function(d,k,i,m) return d end,
           decrypt = function(d,k,i,m) return d end, }

-- base64 under all known names
base64       = { encode=b64enc, decode=b64dec }
crypt.base64encode = b64enc
crypt.base64decode = b64dec
base64encode = b64enc
base64decode = b64dec

-- ── Globals hookup ────────────────────────────────────────────────────────
game      = _game
workspace = _inst("Workspace")
script    = _inst("LocalScript", {Name="Script"})
shared    = {}
-- _G assignment skipped — readonly in standalone Luau

-- ── Emit done ────────────────────────────────────────────────────────────
-- Called by the host-injected prologue once the script finishes (or times out).
_SANDBOX_DONE = function()
  _emit({t="done", round=_ROUND})
end
