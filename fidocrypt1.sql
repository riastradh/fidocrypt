-- -*- Mode: SQL -*-

-- Copyright (c) 2020-2022 Taylor R. Campbell
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.

PRAGMA application_id = 1178817108;     -- 0x46435254, FCRT
PRAGMA user_version = 1;

CREATE TABLE entry (
	id		INTEGER PRIMARY KEY,
	nickname	TEXT UNIQUE,
	credential_id	BLOB NOT NULL UNIQUE,
	ciphertext	BLOB NOT NULL
);

CREATE TABLE relying_party (
	id		INTEGER PRIMARY KEY CHECK(id = 0),
	name		TEXT NOT NULL
);

CREATE TABLE hmac_secret (
	id		INTEGER PRIMARY KEY CHECK(id = 0),
	salt		BLOB NOT NULL CHECK(length(salt) == 32)
);
