--[[
-- util.lua
--
-- nvpass - Neovim secure vault
-- Copyright (C) 2026 ef3d0c3e <ef3d0c3e@pundalik.org>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
--
-- SPDX-License-Identifier: GPL-3.0-or-later
--]]

local M = {
}

function M.err(msg)
	vim.schedule(function()
		vim.notify("[nvpass] " .. msg, vim.log.levels.ERROR)
	end)
end

function M.info(msg)
	vim.schedule(function()
		vim.notify("[nvpass] " .. msg, vim.log.levels.INFO)
	end)
end

--- Assert the binary vault program exists
function M.assert_binary()
	local bin = require("nvpass").config.vault_bin
	if not bin or bin == "" then
		error("[nvpass] vault_bin not configured")
	end
	if vim.fn.executable(bin) ~= 1 then
		error("[nvpass] vault binary not executable: " .. bin)
	end
	return bin
end

--- Prompt for passphrase
function M.prompt_secret(prompt_text)
	local ok, result = pcall(vim.fn.inputsecret, prompt_text)
	if not ok or result == nil or result == "" then return nil end
	return result
end

return M
