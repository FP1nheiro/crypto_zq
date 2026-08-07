local M = {}
function M.add(a, b)
  local t = {}
  for i = 1, 10 do t[i] = a * i + b end
  local s = 0
  for _, v in ipairs(t) do s = s + v end
  if s > 100 then return s, "big" else return s, "small" end
end
function M.greet(name) return "hello " .. tostring(name) end
return M
