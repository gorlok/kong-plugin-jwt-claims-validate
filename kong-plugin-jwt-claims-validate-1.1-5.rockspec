package = "kong-plugin-jwt-claims-validate"
version = "1.1-5"
source = {
   url = "git+https://github.com/gorlok/kong-plugin-jwt-claims-validate",
   tag = "v1.1-5"
}
description = {
   summary = "A Kong plugin to check JWT claim values",
   homepage = "https://github.com/gorlok/kong-plugin-jwt-claims-validate",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.jwt-claims-validate.handler"] = "handler.lua",
      ["kong.plugins.jwt-claims-validate.schema"] = "schema.lua"
   }
}
