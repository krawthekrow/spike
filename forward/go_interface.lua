local godefs = require("godefs")

local GoInterface = {}

function GoInterface:new()
   return setmetatable({},
      {__index = GoInterface})
end

function GoInterface:lookup(five_tuple, five_tuple_len)
   return godefs.Lookup(five_tuple, five_tuple_len)
end

return GoInterface
