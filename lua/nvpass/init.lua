--[[
-- init.lua
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

local M = {}

M.config = {
	vault_bin = nil,
	tmp_path = vim.fn.stdpath("cache") .. "/nvpass/"
}

local util = require("nvpass.util")
local vault = require("nvpass.vault")

--- Per-buffer state
local state = {}

--- Disable some buffer-local features in order to prevent neovim from exposing data from the buffer
local function harden_buffer(buf)
	vim.api.nvim_set_option_value("swapfile", false, { scope = "local" })
	vim.api.nvim_set_option_value("backup", false, { scope = "local" })
	vim.api.nvim_set_option_value("writebackup", false, { scope = "local" })

	vim.api.nvim_set_option_value("undofile", false, { buf = buf })
	vim.api.nvim_set_option_value("modeline", false, { buf = buf })
	vim.api.nvim_set_option_value("bufhidden", "wipe", { buf = buf })
	vim.api.nvim_set_option_value("buftype", "acwrite", { buf = buf }) -- Prevents nvim's usual :w handling
end

--- Erase the per-buffer state for a specific buffer, this clears the passphrase
local function wipe_state(buf)
	local s = state[buf]
	if s then
		s.passphrase = nil
		s.path       = nil
		state[buf]   = nil
		collectgarbage("collect")
	end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Open the virtual vault buffer
-- ─────────────────────────────────────────────────────────────────────────────
local function open_vault_buffer(buf, vault_path, passphrase, decrypted_content)
	state[buf] = { path = vault_path, passphrase = passphrase }

	harden_buffer(buf)
	vim.api.nvim_buf_set_name(buf, vault_path)

	-- Populate with decrypted lines
	local lines = vim.split(decrypted_content, "\n", { plain = true })
	if lines[#lines] == "" then lines[#lines] = nil end -- trim trailing blank
	vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
	vim.bo[buf].modified = false

	-- buftype=acwrite guarantees nvim calls this instead of doing its own write
	local wg = vim.api.nvim_create_augroup("nvpass_write_" .. buf, { clear = true })
	vim.api.nvim_create_autocmd("BufWriteCmd", {
		buffer   = buf,
		group    = wg,
		callback = function()
			local s = state[buf]
			if not s then
				util.err("No vault state for buffer " .. buf .. ", write aborted")
				return
			end

			local lines_now = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
			local plaintext = table.concat(lines_now, "\n") .. "\n"

			local ok, errmsg = vault.encrypt(s.path, plaintext, s.passphrase, M.config.tmp_path)

			plaintext = nil
			collectgarbage("collect")

			if ok then
				vim.bo[buf].modified = false
				util.info("Saved: " .. s.path)
			else
				util.err("Save failed: " .. (errmsg or "unknown"))
			end
		end,
	})

	-- Erase state from the plugin when the buffer is removed from neovim
	local pg = vim.api.nvim_create_augroup("nvpass_wipe_" .. buf, { clear = true })
	vim.api.nvim_create_autocmd("BufWipeout", {
		buffer   = buf,
		group    = pg,
		once     = true,
		callback = function() wipe_state(buf) end,
	})
end

-- ─────────────────────────────────────────────────────────────────────────────
-- BufReadCmd / BufNewFile handler
-- ─────────────────────────────────────────────────────────────────────────────
local function on_open(ev)
	local vault_path = vim.fn.expand("<afile>:p")
	local buf        = ev.buf

	-- Erase and harden on open
	vim.api.nvim_buf_set_lines(buf, 0, -1, false, {})
	harden_buffer(buf)

	local stat = vim.uv.fs_stat(vault_path)
	local is_new = stat == nil or stat.size == 0

	-- Ask user for passphrase, ask for confirmation if file is empty (= new vault file)
	local passphrase
	if is_new then
		passphrase = util.prompt_secret("New vault passphrase: ")
		if not passphrase then
			util.err("Passphrase entry cancelled")
			vim.schedule(function() pcall(vim.api.nvim_buf_delete, buf, { force = true }) end)
			return
		end
		local confirm = util.prompt_secret("Confirm passphrase: ")
		if confirm ~= passphrase then
			passphrase = nil
			confirm = nil
			collectgarbage("collect")
			util.err("Passphrases do not match")
			vim.schedule(function() pcall(vim.api.nvim_buf_delete, buf, { force = true }) end)
			return
		end
		confirm = nil
		collectgarbage("collect")
	else
		passphrase = util.prompt_secret("Vault passphrase: ")
		if not passphrase then
			util.err("Passphrase entry cancelled")
			vim.schedule(function() pcall(vim.api.nvim_buf_delete, buf, { force = true }) end)
			return
		end
	end

	local ok, result
	if is_new then
		ok, result = true, ""
	else
		ok, result = vault.decrypt(vault_path, passphrase)
	end

	if not ok then
		passphrase = nil
		collectgarbage("collect")
		util.err("Could not open vault: " .. (result or "unknown error"))
		vim.schedule(function() pcall(vim.api.nvim_buf_delete, buf, { force = true }) end)
		return
	end

	open_vault_buffer(buf, vault_path, passphrase, result)

	-- Erase from memory
	passphrase = nil
	result     = nil
	collectgarbage("collect")
end

function M.setup(opts)
	if vim.g.loaded_nvpass then
		return
	end
	vim.g.loaded_nvpass = true

	if vim.fn.has("nvim-0.10") == 0 then
		vim.notify("[nvpass] Neovim >= 0.10 is required.", vim.log.levels.ERROR)
		return
	end

	opts = opts or {}
	M.config = vim.tbl_deep_extend("force", M.config, opts)

	-- Make sure vault binary exists
	if not util.assert_binary() then
		return
	end

	local ag = vim.api.nvim_create_augroup("nvpass", { clear = true })

	-- Setup hooks on open
	vim.api.nvim_create_autocmd("BufReadCmd", {
		group    = ag,
		pattern  = "*.nvpass",
		callback = function(ev)
			local ok, msg = pcall(on_open, ev)
			if not ok then
				util.err(tostring(msg))
				pcall(vim.api.nvim_buf_delete, ev.buf, { force = true })
			end
		end,
	})
	vim.api.nvim_create_autocmd("BufNewFile", {
		group    = ag,
		pattern  = "*.nvpass",
		callback = function(ev)
			local ok, msg = pcall(on_open, ev)
			if not ok then
				util.err(tostring(msg))
				pcall(vim.api.nvim_buf_delete, ev.buf, { force = true })
			end
		end,
	})

	-- Block writes if file has .nvpass extension
	vim.api.nvim_create_autocmd("BufWritePre", {
		group    = ag,
		pattern  = "*.nvpass",
		callback = function(ev)
			if not state[ev.buf] then
				vim.bo[ev.buf].modified = false
				util.err("Refusing to write unmanaged vault file")
				return true
			end
		end,
	})
end

return M
