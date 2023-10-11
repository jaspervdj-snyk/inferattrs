-- This is a Pandoc lua filter that will grab snippets (or entire files) and
-- include them in our markdown.

string.startswith = function(self, prefix)
  return string.sub(self, 1, string.len(prefix)) == prefix
end

string.endswith = function(self, suffix)
  return string.sub(self, -string.len(suffix), -1) == suffix
end

function CodeBlock(cb)
  if cb.attributes.snippet then
    local snippet = {}
    local inbraces = false
    for line in io.open(cb.attributes.snippet, "r"):lines() do
      if line:startswith(cb.text) then
        snippet[#snippet + 1] = line
        if line:endswith("{") then
          inbraces = true
        end
      elseif inbraces then
        snippet[#snippet + 1] = line
      end

      if line:startswith("}") then
        inbraces = false
      end
    end
    local text = table.concat(snippet, "\n")
    text = text:gsub("\t", "    ")
    return pandoc.CodeBlock(text, cb.attr), true
  end

  if cb.attributes.include then
    local text = io.open(cb.attributes.include, "r"):read("*all")
    text = text:gsub("\t", "    ")
    return pandoc.CodeBlock(text, cb.attr)
  end

  return cb, true
end
