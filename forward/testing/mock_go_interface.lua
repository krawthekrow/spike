local MockGoInterface = {}

function MockGoInterface:new(opts)
   local use_ipv6 = opts.use_ipv6
   if use_ipv6 == nil then use_ipv6 = false end
   return setmetatable({
      ipv4_backend = opts.ipv4_backend,
      ipv6_backend = opts.ipv6_backend,
      use_ipv6 = use_ipv6
   }, {
      __index = MockGoInterface
   })
end

function MockGoInterface:lookup(five_tuple, five_tuple_len)
   if self.use_ipv6 then
      return self.ipv6_backend, 16
   else
      return self.ipv4_backend, 4
   end
end

return MockGoInterface
