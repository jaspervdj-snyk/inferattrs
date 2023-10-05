string.startswith = function(self, prefix)
    return string.sub(self, 1, string.len(prefix)) == prefix
end

string.endswith = function(self, suffix)
    return string.sub(self, -string.len(suffix), -1) == suffix
end

function CodeBlock(cb)
  local file = cb.attributes.snippet
  if file then
    local included = {}
    local including = false
    for line in io.open("infer.go", "r"):lines() do
      if line:startswith(cb.text) then
        included[#included + 1] = line
        if line:endswith("{") then
          including = true
        end
      elseif including then
        included[#included + 1] = line
      end

      if line:startswith("}") then
        including = false
      end
    end
    return pandoc.CodeBlock(table.concat(included, "\n"), cb.attr), false
  end
  return cb, true
end