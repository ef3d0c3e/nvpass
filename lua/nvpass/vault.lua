--[[
-- vault.lua
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
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <http://www.gnu.org/licenses/>.
--
-- SPDX-License-Identifier: GPL-3.0-or-later
--]]

local M = {
}

local util = require("nvpass.util")

--- Decrypt the vault
function M.decrypt(vault_path, passphrase)
	local bin = util.assert_binary()

	--- Setup pipes
	local stdout_pipe = vim.uv.new_pipe(false)
	local stderr_pipe = vim.uv.new_pipe(false)
	local pass_pipe = vim.uv.new_pipe(false)

	if not stdout_pipe or not stderr_pipe or not pass_pipe then
		return false, "failed to allocate pipes"
	end

	local out_chunks = {} -- stdout
	local err_chunks = {} -- stderr
	local exit_code = nil -- program exit code
	local done = false

	-- fd 1 (stdout) plaintext output
	-- fd 3 passphrase pipe
	local handle, spawn_err_msg = vim.uv.spawn(bin, {
		args = { "-d", vault_path, "-", "--passphrase-fd", "3" },
		stdio = { nil, stdout_pipe, stderr_pipe, pass_pipe },
	}, function(code, _signal)
		exit_code = code
		done = true
	end)

	if not handle then
		stdout_pipe:close(); stderr_pipe:close(); pass_pipe:close()
		return false, "spawn failed: " .. tostring(spawn_err_msg)
	end

	-- Write passphrase to pass_pipe (fd 3)
	pass_pipe:write(passphrase .. "\n", function(_we)
		pass_pipe:shutdown(function()
			pass_pipe:close()
		end)
	end)

	-- Read vault program response on stdout_pipe
	stdout_pipe:read_start(function(re, data)
		if re then
			stdout_pipe:close(); return
		end
		if data then out_chunks[#out_chunks + 1] = data else stdout_pipe:close() end
	end)

	-- Read vault program stderr
	stderr_pipe:read_start(function(re, data)
		if re then
			stderr_pipe:close(); return
		end
		if data then err_chunks[#err_chunks + 1] = data else stderr_pipe:close() end
	end)

	-- Wait for completion. TODO: This should be handled more carefully, e.g SIGKILL after a while, while making sure we don't create zombies
	vim.wait(10000, function() return done end, 5)
	-- Release libuv res
	handle:close()

	local content = table.concat(out_chunks)
	local err_msg = table.concat(err_chunks)

	-- Wipe stdout chunks and collect garbage
	for i = 1, #out_chunks do out_chunks[i] = nil end
	collectgarbage("collect")

	if exit_code ~= 0 or #err_msg ~= 0 then
		return false, "decryption failed: " .. (err_msg ~= "" and err_msg or "exit " .. tostring(exit_code))
	end

	return true, content
end

--- Encrypt the vault. This function first writes to a temporary file to make sure we don't overwrite the vault file with garbage data in cases of failures
function M.encrypt(vault_path, plaintext, passphrase, tmp_dir)
	local bin = util.assert_binary()
	-- Create temp dir if it doesn't exist
	if not vim.uv.fs_stat(tmp_dir) then
		local ok, msg, _ = vim.uv.fs_mkdir(tmp_dir, tonumber('775', 8))
		if not ok then
			return false, "failed to create nvpass temporary directory: " .. msg
		end
	end
	local tmp_path = tmp_dir .. "nvpass_vault_" .. tostring(math.random(100000, 999999))

	-- Setup pipes
	local stdin_pipe = vim.uv.new_pipe(false) -- Stdin, contains plaintext
	local stderr_pipe = vim.uv.new_pipe(false) -- Errors
	local pass_pipe = vim.uv.new_pipe(false) -- Passphrase pipe (fd 3)

	if not stdin_pipe or not stderr_pipe or not pass_pipe then
		return false, "failed to allocate pipes"
	end

	local err_chunks = {}
	local exit_code = nil
	local done = false

	-- Spawn vault
	local handle, spawn_err_msg = vim.uv.spawn(bin, {
		args = { "-e", "-", tmp_path, "--passphrase-fd", "3" },
		stdio = { stdin_pipe, nil, stderr_pipe, pass_pipe },
	}, function(code, _signal)
		exit_code = code
		done = true
	end)

	if not handle then
		stdin_pipe:close(); stderr_pipe:close(); pass_pipe:close()
		return false, "spawn failed: " .. tostring(spawn_err_msg)
	end

	-- Send passphrase on fd 3
	pass_pipe:write(passphrase .. "\n", function(_we)
		pass_pipe:shutdown(function()
			pass_pipe:close()
		end)
	end)

	-- Send plaintext on stdin
	stdin_pipe:write(plaintext, function(_we)
		stdin_pipe:shutdown(function()
			stdin_pipe:close()
		end)
	end)

	-- Read potential errors
	stderr_pipe:read_start(function(re, data)
		if re then
			stderr_pipe:close(); return
		end
		if data then err_chunks[#err_chunks + 1] = data else stderr_pipe:close() end
	end)

	vim.wait(10000, function() return done end, 5)

	handle:close()

	local err_msg = table.concat(err_chunks)

	if exit_code ~= 0 or #err_msg ~= 0 then
		vim.uv.fs_unlink(tmp_path) -- Delete temporary
		return false, "encryption failed: " .. (err_msg ~= "" and err_msg or "exit " .. tostring(exit_code))
	end


	-- Replace original vault file with the new version
	local ok, rename_err = vim.uv.fs_rename(tmp_path, vault_path)
	if not ok then
		vim.uv.fs_unlink(tmp_path) -- Delete temporary
		return false, "rename failed: " .. tostring(rename_err)
	end

	return true, nil
end

return M
