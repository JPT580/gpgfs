# GPGFS

GPG encryption for synchronized folders.

    Usage: gpgfs <gpg_keyid> <encrypted_root> <mountpoint>


gpg_keyid: The identity of the gpg key to use. (See gpg -K)

encrypted_root: Path to folder where to store the encrypted data in.

mountpoint: Where to mount the filesystem.

# File structure

This represents the structure GPGFS will use to store the encrypted data on disk.

    gpgfs/index
    gpgfs/a/b

# Dependencies

GPGFS needs python3 and fuse support to run.

You can install the python dependencies using pip: (using a virtualenv may be helpful)

    pip install -r requirements.txt

# Test suites

* ntfs-3g
  http://sourceforge.net/p/ntfs-3g/pjd-fstest/ci/master/tree/

* tuxera
  http://www.tuxera.com/community/posix-test-suite/

# BSD licensed

Copyright © 2014, Jarno Seppänen
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
