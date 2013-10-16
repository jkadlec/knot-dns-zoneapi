/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <tests/tap/basic.h>

#include "knot/server/journal.h"
#include "knot/knot.h"


/*! \brief Generate random string with given length. */
static int randstr(char* dst, size_t len)
{
	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';

	return 0;
}

/*! \brief Walk journal of chars into buffer. */
static int  _wbi = 0;
static char _walkbuf[7];
static int walkchars_cmp(uint64_t k1, uint64_t k2) {
	return k1 - k2;
}

static int walkchars(journal_t *j, journal_node_t *n) {
	journal_read(j, n->id, walkchars_cmp, _walkbuf + _wbi);
	++_wbi;
	return 0;
}

int main(int argc, char *argv[])
{
	plan(24);

	/* Create tmpdir */
	int fsize = 8092;
	int jsize = 6;
	char *tmpdir = test_tmpdir();
	char jfn_buf[4096];
	snprintf(jfn_buf, 4096 - 1, "%s/%s", tmpdir, "journal.XXXXXX");

	/* Test 1: Create tmpfile. */
	int tmp_fd = mkstemp(jfn_buf);
	ok(tmp_fd >= 0, "journal: create temporary file");
	if (tmp_fd < 0) {
		skip_block(20, NULL);
		goto skip_all;
	}
	close(tmp_fd);

	/* Test 2: Create journal. */
	const char *jfilename = jfn_buf;
	int ret = journal_create(jfilename, jsize);
	is_int(KNOT_EOK, ret, "journal: create journal '%s'", jfilename);

	/* Test 3: Open journal. */
	journal_t *journal = journal_open(jfilename, fsize, JOURNAL_LAZY, 0);
	ok(journal != NULL, "journal: open journal '%s'", jfilename);

	/* Retain journal. */
	journal_t *j = journal_retain(journal);

	/* Test 4: Write entry to log. */
	const char *sample = "deadbeef";
	ret = journal_write(j, 0x0a, sample, strlen(sample));
	is_int(KNOT_EOK, ret, "journal: write");

	/* Test 5: Read entry from log. */
	char tmpbuf[64] = {'\0'};
	ret = journal_read(j, 0x0a, 0, tmpbuf);
	is_int(KNOT_EOK, ret, "journal: read entry");

	/* Test 6: Compare read data. */
	ret = strncmp(sample, tmpbuf, strlen(sample));
	is_int(KNOT_EOK, ret, "journal: read data integrity check");

	/* Append several characters. */
	journal_write(j, 0, "X", 1); /* Dummy */
	char word[7] =  { 'w', 'o', 'r', 'd', '0', '\0', '\0' };
	for (int i = 0; i < strlen(word); ++i) {
		journal_write(j, i, word+i, 1);
	}

	/* Test 7: Compare journal_walk() result. */
	_wbi = 0;
	journal_walk(j, walkchars);
	_walkbuf[_wbi] = '\0';
	ret = strcmp(word, _walkbuf);
	is_int(0, ret, "journal: read data integrity check 2 '%s'", _walkbuf);
	_wbi = 0;

	/* Test 8: Change single letter and compare. */
	word[5] = 'X';
	journal_write(j, 5, word+5, 1); /* append 'X', shifts out 'w' */
	journal_walk(j, walkchars);
	_walkbuf[_wbi] = '\0';
	ret = strcmp(word + 1, _walkbuf);
	is_int(0, ret, "journal: read data integrity check 3 '%s'", _walkbuf);
	_wbi = 0;

	/* Test 9: Attempt to retain and release. */
	journal_t *tmp = journal_retain(j);
	ok(tmp == j, "journal: tested journal retaining");
	journal_release(tmp);

	/* Release journal. */
	journal_release(j);

	/* Close journal. */
	journal_close(journal);

	/* Recreate journal = NORMAL mode. */
	if (remove(jfilename) < 0) {
		diag("journal: couldn't remove filename");
	}
	fsize = 8092;
	jsize = 512;
	ret = journal_create(jfilename, jsize);
	is_int(KNOT_EOK, ret, "journal: create journal '%s'", jfilename);

	j = journal_open(jfilename, fsize, 0, 0);
	ok(j != NULL, "journal: open journal '%s'", jfilename);

	/* Test 10: Write random data. */
	int chk_key = 0;
	char chk_buf[64] = {'\0'};
	ret = 0;
	const int itcount = jsize * 5 + 5;
	for (int i = 0; i < itcount; ++i) {
		int key = rand() % 65535;
		randstr(tmpbuf, sizeof(tmpbuf));
		if (journal_write(j, key, tmpbuf, sizeof(tmpbuf)) != KNOT_EOK) {
			ret = -1;
			break;
		}

		/* Store some key on the end. */
		if (i == itcount - 2) {
			chk_key = key;
			memcpy(chk_buf, tmpbuf, sizeof(chk_buf));
		}
	}
	is_int(0, ret, "journal: sustained looped writes");

	/* Test 11: Check data integrity. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	journal_read(j, chk_key, 0, tmpbuf);
	ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
	is_int(0, ret, "journal: read data integrity check");

	/* Test 12: Reopen log and re-read value. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	journal_close(j);
	j = journal_open(jfilename, fsize, 0, 0);
	ok(j != NULL, "journal: open journal '%s'", jfilename);

	journal_read(j, chk_key, 0, tmpbuf);
	ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
	is_int(0, ret, "journal: read data integrity check after close/open");

	/* Test 13: Map journal entry. */
	char *mptr = NULL;
	memset(chk_buf, 0xde, sizeof(chk_buf));
	ret = journal_map(j, 0x12345, &mptr, sizeof(chk_buf));
	ok(mptr && ret == 0, "journal: mapped journal entry");
	if (ret != 0) {
		skip_block(2, NULL);
	} else {

	/* Test 14: Write to mmaped entry and unmap. */
	memcpy(mptr, chk_buf, sizeof(chk_buf));
	ret = journal_unmap(j, 0x12345, mptr, 1);
	ok(mptr && ret == 0, "journal: written to mapped entry and finished");

	/* Test 15: Compare mmaped entry. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	journal_read(j, 0x12345, NULL, tmpbuf);
	ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
	ok(ret == 0, "journal: mapped entry data integrity check");

	} /* end skip */

	/* Test 16: Make a transaction. */
	uint64_t tskey = 0x75750000;
	ret = journal_trans_begin(j);
	is_int(0, ret, "journal: TRANS begin");
	for (int i = 0; i < 16; ++i) {
		memset(tmpbuf, i, sizeof(tmpbuf));
		journal_write(j, tskey + i, tmpbuf, sizeof(tmpbuf));
	}

	/* Test 17: Check if uncommited node exists. */
	ret = journal_read(j, tskey + rand() % 16, NULL, chk_buf);
	ok(ret != 0, "journal: check for uncommited node");

	/* Test 18: Commit transaction. */
	ret = journal_trans_commit(j);
	int read_ret = journal_read(j, tskey + rand() % 16, NULL, chk_buf);
	ok(ret == 0 && read_ret == 0, "journal: transaction commit");

	/* Test 19: Rollback transaction. */
	tskey = 0x6B6B0000;
	journal_trans_begin(j);
	for (int i = 0; i < 16; ++i) {
		memset(tmpbuf, i, sizeof(tmpbuf));
		journal_write(j, tskey + i, tmpbuf, sizeof(tmpbuf));
	}
	ret = journal_trans_rollback(j);
	read_ret = journal_read(j, tskey + rand() % 16, NULL, chk_buf);
	ok(ret == 0 && read_ret != 0, "journal: transaction rollback");

	/* Test 20: Write random data. */
	ret = 0;
	for (int i = 0; i < 512; ++i) {
		int key = i;
		randstr(tmpbuf, sizeof(tmpbuf));
		ret = journal_map(j, key, &mptr, sizeof(tmpbuf));
		if (ret != KNOT_EOK) {
			diag("journal_map failed: %s", knot_strerror(ret));
			break;
		}
		memcpy(mptr, tmpbuf, sizeof(tmpbuf));
		if ((ret = journal_unmap(j, key, mptr, 1)) != KNOT_EOK) {
			diag("journal_unmap failed: %s", knot_strerror(ret));
			break;
		}

		/* Store some key on the end. */
		memset(chk_buf, 0, sizeof(chk_buf));
		ret = journal_read(j, key, 0, chk_buf);
		if (ret != 0) {
			diag("journal_map integrity check failed %s",
			     knot_strerror(ret));
			break;
		}
		ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
		if (ret != 0) {
			diag("journal_map integrity check failed");
			break;
		}
	}
	is_int(0, ret, "journal: sustained mmap r/w");

	/* Test 21: Open + create journal. */
	journal_close(j);
	remove(jfilename);
	j = journal_open(jfilename, fsize, 0, 0);
	ok(j != NULL, "journal: open+create from scratch '%s'", jfilename);

	/* Close journal. */
	journal_close(j);

skip_all:
	/* Delete journal. */
	remove(jfilename);

	return 0;
}