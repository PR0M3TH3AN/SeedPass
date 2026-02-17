# CI Health Agent Check Failed

The repository checks failed during the CI run.

## Check Failures

1.  **flake8**: Failed (exit code 1).
    - Found style violations (E402, E501, etc.).
2.  **pytest**: Passed (exit code 0).
    - Tests passed successfully.

## Details

### flake8 Output
```
./scripts/generate_test_profile.py:32:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:34:80: E501 line too long (80 > 79 characters)
./scripts/generate_test_profile.py:39:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:40:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:41:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:42:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:43:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:44:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:45:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:46:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:47:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:48:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:49:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:50:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:51:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:52:1: E402 module level import not at top of file
./scripts/generate_test_profile.py:60:80: E501 line too long (98 > 79 characters)
./scripts/generate_test_profile.py:107:80: E501 line too long (80 > 79 characters)
./scripts/generate_test_profile.py:139:80: E501 line too long (84 > 79 characters)
./scripts/generate_test_profile.py:141:80: E501 line too long (88 > 79 characters)
./scripts/generate_test_profile.py:172:80: E501 line too long (82 > 79 characters)
./scripts/generate_test_profile.py:189:80: E501 line too long (86 > 79 characters)
./scripts/generate_test_profile.py:218:80: E501 line too long (87 > 79 characters)
./scripts/generate_test_profile.py:221:80: E501 line too long (86 > 79 characters)
./scripts/update_checksum.py:10:1: E402 module level import not at top of file
./scripts/update_checksum.py:11:1: E402 module level import not at top of file
./scripts/update_checksum.py:15:80: E501 line too long (86 > 79 characters)
./src/constants.py:39:80: E501 line too long (86 > 79 characters)
./src/local_bip85/__init__.py:12:80: E501 line too long (94 > 79 characters)
./src/local_bip85/bip85.py:6:80: E501 line too long (97 > 79 characters)
./src/local_bip85/bip85.py:7:80: E501 line too long (101 > 79 characters)
./src/local_bip85/bip85.py:8:80: E501 line too long (100 > 79 characters)
./src/local_bip85/bip85.py:10:80: E501 line too long (160 > 79 characters)
./src/local_bip85/bip85.py:11:80: E501 line too long (167 > 79 characters)
./src/local_bip85/bip85.py:13:80: E501 line too long (87 > 79 characters)
./src/local_bip85/bip85.py:16:1: F401 'sys' imported but unused
./src/local_bip85/bip85.py:20:1: F401 'os' imported but unused
./src/local_bip85/bip85.py:25:80: E501 line too long (82 > 79 characters)
./src/local_bip85/bip85.py:27:1: F401 'cryptography.hazmat.primitives.kdf.hkdf.HKDF' imported but unused
./src/local_bip85/bip85.py:28:1: F401 'cryptography.hazmat.primitives.hashes' imported but unused
./src/local_bip85/bip85.py:29:1: F401 'cryptography.hazmat.backends.default_backend' imported but unused
./src/local_bip85/bip85.py:54:80: E501 line too long (83 > 79 characters)
./src/local_bip85/bip85.py:57:80: E501 line too long (82 > 79 characters)
./src/local_bip85/bip85.py:74:80: E501 line too long (80 > 79 characters)
./src/local_bip85/bip85.py:77:80: E501 line too long (82 > 79 characters)
./src/local_bip85/bip85.py:109:80: E501 line too long (102 > 79 characters)
./src/local_bip85/bip85.py:112:80: E501 line too long (119 > 79 characters)
./src/local_bip85/bip85.py:115:80: E501 line too long (102 > 79 characters)
./src/local_bip85/bip85.py:139:80: E501 line too long (82 > 79 characters)
./src/local_bip85/bip85.py:152:80: E501 line too long (83 > 79 characters)
./src/main.py:5:80: E501 line too long (82 > 79 characters)
./src/main.py:10:1: E402 module level import not at top of file
./src/main.py:11:1: E402 module level import not at top of file
./src/main.py:12:1: E402 module level import not at top of file
./src/main.py:13:1: E402 module level import not at top of file
./src/main.py:14:1: E402 module level import not at top of file
./src/main.py:15:1: E402 module level import not at top of file
./src/main.py:16:1: E402 module level import not at top of file
./src/main.py:17:1: E402 module level import not at top of file
./src/main.py:18:1: E402 module level import not at top of file
./src/main.py:19:1: E402 module level import not at top of file
./src/main.py:20:1: E402 module level import not at top of file
./src/main.py:21:1: E402 module level import not at top of file
./src/main.py:23:1: E402 module level import not at top of file
./src/main.py:24:1: F401 'nostr.client.NostrClient' imported but unused
./src/main.py:24:1: E402 module level import not at top of file
./src/main.py:25:1: E402 module level import not at top of file
./src/main.py:26:1: E402 module level import not at top of file
./src/main.py:27:1: E402 module level import not at top of file
./src/main.py:28:1: E402 module level import not at top of file
./src/main.py:33:1: E402 module level import not at top of file
./src/main.py:40:1: E402 module level import not at top of file
./src/main.py:41:1: E402 module level import not at top of file
./src/main.py:42:1: E402 module level import not at top of file
./src/main.py:47:1: E402 module level import not at top of file
./src/main.py:65:80: E501 line too long (85 > 79 characters)
./src/main.py:177:80: E501 line too long (97 > 79 characters)
./src/main.py:197:80: E501 line too long (87 > 79 characters)
./src/main.py:202:80: E501 line too long (88 > 79 characters)
./src/main.py:243:80: E501 line too long (128 > 79 characters)
./src/main.py:263:80: E501 line too long (85 > 79 characters)
./src/main.py:305:80: E501 line too long (80 > 79 characters)
./src/main.py:335:80: E501 line too long (81 > 79 characters)
./src/main.py:442:80: E501 line too long (87 > 79 characters)
./src/main.py:455:80: E501 line too long (80 > 79 characters)
./src/main.py:481:80: E501 line too long (83 > 79 characters)
./src/main.py:489:80: E501 line too long (107 > 79 characters)
./src/main.py:491:80: E501 line too long (85 > 79 characters)
./src/main.py:503:80: E501 line too long (88 > 79 characters)
./src/main.py:604:80: E501 line too long (99 > 79 characters)
./src/main.py:813:80: E501 line too long (84 > 79 characters)
./src/main.py:863:80: E501 line too long (85 > 79 characters)
./src/main.py:864:80: E501 line too long (81 > 79 characters)
./src/main.py:900:80: E501 line too long (85 > 79 characters)
./src/main.py:901:80: E501 line too long (81 > 79 characters)
./src/main.py:922:80: E501 line too long (81 > 79 characters)
./src/main.py:971:80: E501 line too long (81 > 79 characters)
./src/main.py:1015:80: E501 line too long (81 > 79 characters)
./src/main.py:1048:80: E501 line too long (82 > 79 characters)
./src/main.py:1089:80: E501 line too long (84 > 79 characters)
./src/main.py:1092:80: E501 line too long (85 > 79 characters)
./src/main.py:1117:80: E501 line too long (84 > 79 characters)
./src/main.py:1138:80: E501 line too long (81 > 79 characters)
./src/main.py:1152:80: E501 line too long (85 > 79 characters)
./src/main.py:1180:80: E501 line too long (85 > 79 characters)
./src/main.py:1256:80: E501 line too long (85 > 79 characters)
./src/main.py:1283:80: E501 line too long (82 > 79 characters)
./src/main.py:1286:80: E501 line too long (82 > 79 characters)
./src/main.py:1354:80: E501 line too long (84 > 79 characters)
./src/main.py:1385:80: E501 line too long (82 > 79 characters)
./src/main.py:1388:80: E501 line too long (87 > 79 characters)
./src/main.py:1391:80: E501 line too long (81 > 79 characters)
./src/main.py:1392:80: E501 line too long (82 > 79 characters)
./src/main.py:1395:80: E501 line too long (81 > 79 characters)
./src/main.py:1396:80: E501 line too long (82 > 79 characters)
./src/main.py:1429:80: E501 line too long (83 > 79 characters)
./src/main.py:1468:80: E501 line too long (85 > 79 characters)
./src/main.py:1469:80: E501 line too long (87 > 79 characters)
./src/main.py:1484:80: E501 line too long (84 > 79 characters)
./src/nostr/client.py:1:1: F401 'asyncio' imported but unused
./src/nostr/client.py:2:1: F401 'base64' imported but unused
./src/nostr/client.py:3:1: F401 'json' imported but unused
./src/nostr/client.py:5:1: F401 'time' imported but unused
./src/nostr/client.py:7:1: F401 'datetime.timedelta' imported but unused
./src/nostr/client.py:10:1: F401 'websockets' imported but unused
./src/nostr/client.py:11:1: F401 'nostr_sdk.EventBuilder' imported but unused
./src/nostr/client.py:11:1: F401 'nostr_sdk.Filter' imported but unused
./src/nostr/client.py:11:1: F401 'nostr_sdk.Kind' imported but unused
./src/nostr/client.py:11:1: F401 'nostr_sdk.KindStandard' imported but unused
./src/nostr/client.py:11:1: F401 'nostr_sdk.Tag' imported but unused
./src/nostr/client.py:11:1: F401 'nostr_sdk.RelayUrl' imported but unused
./src/nostr/client.py:11:1: F401 'nostr_sdk.PublicKey' imported but unused
./src/nostr/client.py:22:1: F401 'nostr_sdk.EventId' imported but unused
./src/nostr/client.py:22:1: F401 'nostr_sdk.Timestamp' imported but unused
./src/nostr/client.py:24:1: F401 'constants.MAX_RETRIES' imported but unused
./src/nostr/client.py:24:1: F401 'constants.RETRY_DELAY' imported but unused
./src/nostr/client.py:27:1: F401 '.backup_models.ChunkMeta' imported but unused
./src/nostr/client.py:27:1: F401 '.backup_models.KIND_DELTA' imported but unused
./src/nostr/client.py:27:1: F401 '.backup_models.KIND_MANIFEST' imported but unused
./src/nostr/client.py:27:1: F401 '.backup_models.KIND_SNAPSHOT_CHUNK' imported but unused
./src/nostr/coincurve_keys.py:4:1: F401 'coincurve.PublicKey' imported but unused
./src/nostr/connection.py:93:80: E501 line too long (80 > 79 characters)
./src/nostr/connection.py:99:80: E501 line too long (84 > 79 characters)
./src/nostr/connection.py:103:80: E501 line too long (83 > 79 characters)
./src/nostr/connection.py:132:80: E501 line too long (87 > 79 characters)
./src/nostr/connection.py:140:80: E501 line too long (81 > 79 characters)
./src/nostr/connection.py:167:80: E501 line too long (85 > 79 characters)
./src/nostr/connection.py:209:80: E501 line too long (82 > 79 characters)
./src/nostr/key_manager.py:22:80: E501 line too long (82 > 79 characters)
./src/nostr/key_manager.py:33:80: E501 line too long (82 > 79 characters)
./src/nostr/key_manager.py:50:80: E501 line too long (89 > 79 characters)
./src/nostr/key_manager.py:100:80: E501 line too long (86 > 79 characters)
./src/nostr/key_manager.py:108:80: E501 line too long (81 > 79 characters)
./src/nostr/key_manager.py:119:80: E501 line too long (85 > 79 characters)
./src/nostr/snapshot.py:34:27: E203 whitespace before ':'
./src/nostr/snapshot.py:34:80: E501 line too long (82 > 79 characters)
./src/nostr/snapshot.py:58:80: E501 line too long (82 > 79 characters)
./src/nostr/snapshot.py:90:80: E501 line too long (83 > 79 characters)
./src/nostr/snapshot.py:94:80: E501 line too long (80 > 79 characters)
./src/nostr/snapshot.py:121:80: E501 line too long (86 > 79 characters)
./src/nostr/snapshot.py:188:80: E501 line too long (82 > 79 characters)
./src/nostr/snapshot.py:230:80: E501 line too long (87 > 79 characters)
./src/nostr/snapshot.py:279:80: E501 line too long (81 > 79 characters)
./src/nostr/snapshot.py:296:80: E501 line too long (89 > 79 characters)
./src/nostr/snapshot.py:300:80: E501 line too long (84 > 79 characters)
./src/nostr/snapshot.py:343:80: E501 line too long (88 > 79 characters)
./src/nostr/snapshot.py:375:80: E501 line too long (82 > 79 characters)
./src/nostr/snapshot.py:385:80: E501 line too long (82 > 79 characters)
./src/nostr/snapshot.py:408:80: E501 line too long (81 > 79 characters)
./src/seedpass/api.py:10:1: F401 'typing.Optional' imported but unused
./src/seedpass/api.py:35:80: E501 line too long (80 > 79 characters)
./src/seedpass/api.py:67:80: E501 line too long (88 > 79 characters)
./src/seedpass/api.py:87:80: E501 line too long (82 > 79 characters)
./src/seedpass/api.py:167:80: E501 line too long (80 > 79 characters)
./src/seedpass/api.py:187:80: E501 line too long (83 > 79 characters)
./src/seedpass/api.py:288:80: E501 line too long (81 > 79 characters)
./src/seedpass/api.py:363:80: E501 line too long (81 > 79 characters)
./src/seedpass/api.py:422:80: E501 line too long (80 > 79 characters)
./src/seedpass/api.py:475:80: E501 line too long (83 > 79 characters)
./src/seedpass/api.py:514:80: E501 line too long (88 > 79 characters)
./src/seedpass/api.py:521:80: E501 line too long (84 > 79 characters)
./src/seedpass/api.py:564:80: E501 line too long (82 > 79 characters)
./src/seedpass/api.py:690:80: E501 line too long (85 > 79 characters)
./src/seedpass/cli/__init__.py:42:1: E402 module level import not at top of file
./src/seedpass/cli/__init__.py:117:80: E501 line too long (87 > 79 characters)
./src/seedpass/cli/__init__.py:121:80: E501 line too long (87 > 79 characters)
./src/seedpass/cli/__init__.py:125:80: E501 line too long (87 > 79 characters)
./src/seedpass/cli/__init__.py:135:80: E501 line too long (89 > 79 characters)
./src/seedpass/cli/__init__.py:148:80: E501 line too long (88 > 79 characters)
./src/seedpass/cli/__init__.py:167:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/__init__.py:175:80: E501 line too long (84 > 79 characters)
./src/seedpass/cli/api.py:12:80: E501 line too long (85 > 79 characters)
./src/seedpass/cli/api.py:16:80: E501 line too long (90 > 79 characters)
./src/seedpass/cli/common.py:6:1: F401 'seedpass.core.entry_types.EntryType' imported but unused
./src/seedpass/cli/common.py:7:1: F401 'seedpass.core.api.ChangePasswordRequest' imported but unused
./src/seedpass/cli/common.py:7:1: F401 'seedpass.core.api.UnlockRequest' imported but unused
./src/seedpass/cli/common.py:7:1: F401 'seedpass.core.api.BackupParentSeedRequest' imported but unused
./src/seedpass/cli/common.py:7:1: F401 'seedpass.core.api.ProfileSwitchRequest' imported but unused
./src/seedpass/cli/common.py:7:1: F401 'seedpass.core.api.ProfileRemoveRequest' imported but unused
./src/seedpass/cli/config.py:61:80: E501 line too long (86 > 79 characters)
./src/seedpass/cli/config.py:72:80: E501 line too long (85 > 79 characters)
./src/seedpass/cli/config.py:107:80: E501 line too long (87 > 79 characters)
./src/seedpass/cli/entry.py:30:80: E501 line too long (80 > 79 characters)
./src/seedpass/cli/entry.py:90:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/entry.py:129:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/entry.py:175:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/entry.py:176:80: E501 line too long (81 > 79 characters)
./src/seedpass/cli/entry.py:200:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/entry.py:217:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/entry.py:238:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/entry.py:255:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/entry.py:288:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/fingerprint.py:29:80: E501 line too long (81 > 79 characters)
./src/seedpass/cli/nostr.py:8:80: E501 line too long (101 > 79 characters)
./src/seedpass/cli/util.py:20:80: E501 line too long (82 > 79 characters)
./src/seedpass/cli/vault.py:46:80: E501 line too long (84 > 79 characters)
./src/seedpass/cli/vault.py:93:80: E501 line too long (80 > 79 characters)
./src/seedpass/cli/vault.py:97:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/api.py:5:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/api.py:142:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/api.py:206:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/api.py:218:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/api.py:224:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/api.py:251:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/api.py:292:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/api.py:301:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/api.py:303:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/api.py:541:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/api.py:570:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/api.py:668:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/backup.py:6:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/backup.py:7:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/backup.py:11:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/backup.py:24:1: F401 'constants.APP_DIR' imported but unused
./src/seedpass/core/backup.py:34:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/backup.py:58:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/backup.py:68:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/backup.py:81:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/backup.py:87:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/backup.py:96:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/backup.py:104:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/backup.py:124:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/backup.py:131:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/backup.py:134:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/backup.py:139:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/backup.py:143:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/backup.py:154:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/backup.py:159:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/backup.py:162:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/backup.py:166:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/backup.py:188:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/backup.py:194:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/backup.py:199:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/backup.py:209:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/backup.py:212:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/backup.py:217:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/backup.py:221:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/config_manager.py:88:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/config_manager.py:101:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/config_manager.py:265:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:11:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:38:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/encryption.py:40:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:50:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/encryption.py:69:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/encryption.py:78:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/encryption.py:85:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/encryption.py:88:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/encryption.py:101:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/encryption.py:127:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/encryption.py:142:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:146:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/encryption.py:159:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:164:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:169:80: E501 line too long (98 > 79 characters)
./src/seedpass/core/encryption.py:174:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/encryption.py:177:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/encryption.py:181:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/encryption.py:186:80: E501 line too long (96 > 79 characters)
./src/seedpass/core/encryption.py:201:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:207:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/encryption.py:209:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/encryption.py:218:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:220:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/encryption.py:240:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/encryption.py:245:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/encryption.py:248:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:277:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/encryption.py:287:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/encryption.py:292:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/encryption.py:293:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/encryption.py:298:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/encryption.py:326:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/encryption.py:331:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/encryption.py:375:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/encryption.py:393:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/encryption.py:403:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/encryption.py:418:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/encryption.py:430:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/encryption.py:467:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/encryption.py:474:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/encryption.py:494:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/encryption.py:500:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/encryption.py:504:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/encryption.py:519:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:523:80: E501 line too long (93 > 79 characters)
./src/seedpass/core/encryption.py:537:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/encryption.py:552:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/encryption.py:576:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/encryption.py:579:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/encryption.py:585:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/encryption.py:606:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/encryption.py:619:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/encryption.py:627:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/encryption.py:634:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/encryption.py:635:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/entry_management.py:7:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:8:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/entry_management.py:11:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:13:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/entry_management.py:14:80: E501 line too long (92 > 79 characters)
./src/seedpass/core/entry_management.py:15:80: E501 line too long (101 > 79 characters)
./src/seedpass/core/entry_management.py:23:5: F401 'json as json_lib' imported but unused
./src/seedpass/core/entry_management.py:70:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:74:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:92:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_management.py:117:80: E501 line too long (95 > 79 characters)
./src/seedpass/core/entry_management.py:179:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/entry_management.py:225:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:233:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:369:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_management.py:375:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:435:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:529:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:747:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_management.py:773:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/entry_management.py:775:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:784:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_management.py:799:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/entry_management.py:805:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:810:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_management.py:813:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/entry_management.py:862:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/entry_management.py:866:80: E501 line too long (103 > 79 characters)
./src/seedpass/core/entry_management.py:872:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:976:80: E501 line too long (102 > 79 characters)
./src/seedpass/core/entry_management.py:982:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:985:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:988:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:992:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:997:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:1001:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:1006:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_management.py:1021:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/entry_management.py:1062:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/entry_management.py:1071:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:1075:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/entry_management.py:1077:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:1131:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:1141:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:1151:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_management.py:1154:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:1162:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_management.py:1172:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_management.py:1185:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:1187:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/entry_management.py:1191:80: E501 line too long (106 > 79 characters)
./src/seedpass/core/entry_management.py:1198:80: E501 line too long (91 > 79 characters)
./src/seedpass/core/entry_management.py:1204:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:1207:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/entry_management.py:1210:80: E501 line too long (123 > 79 characters)
./src/seedpass/core/entry_management.py:1215:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:1218:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/entry_management.py:1235:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_management.py:1237:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:1252:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_management.py:1262:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_management.py:1304:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:1309:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/entry_management.py:1313:80: E501 line too long (103 > 79 characters)
./src/seedpass/core/entry_management.py:1319:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/entry_management.py:1321:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_management.py:1326:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/entry_management.py:1339:27: F541 f-string is missing placeholders
./src/seedpass/core/entry_management.py:1357:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:1370:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:1379:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_management.py:1383:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:1412:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_management.py:1436:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_service.py:41:80: E501 line too long (90 > 79 characters)
./src/seedpass/core/entry_service.py:47:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/entry_service.py:51:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_service.py:54:80: E501 line too long (123 > 79 characters)
./src/seedpass/core/entry_service.py:66:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_service.py:70:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_service.py:80:80: E501 line too long (119 > 79 characters)
./src/seedpass/core/entry_service.py:85:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_service.py:92:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_service.py:94:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_service.py:99:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_service.py:114:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_service.py:132:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/entry_service.py:146:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_service.py:168:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/entry_service.py:183:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_service.py:185:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/entry_service.py:191:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/entry_service.py:193:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/entry_service.py:195:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/entry_service.py:197:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/entry_service.py:205:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/entry_service.py:231:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:6:80: E501 line too long (92 > 79 characters)
./src/seedpass/core/manager.py:7:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:8:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:23:1: F401 'builtins' imported but unused
./src/seedpass/core/manager.py:44:1: F401 'utils.key_derivation.derive_key_from_parent_seed' imported but unused
./src/seedpass/core/manager.py:53:1: F401 'utils.checksum.json_checksum' imported but unused
./src/seedpass/core/manager.py:69:1: F401 'utils.terminal_utils.clear_screen' imported but unused
./src/seedpass/core/manager.py:69:1: F401 'utils.terminal_utils.clear_and_print_profile_chain' imported but unused
./src/seedpass/core/manager.py:81:1: F401 'constants.PARENT_SEED_FILE' imported but unused
./src/seedpass/core/manager.py:81:1: F401 'constants.MIN_PASSWORD_LENGTH' imported but unused
./src/seedpass/core/manager.py:81:1: F401 'constants.MAX_PASSWORD_LENGTH' imported but unused
./src/seedpass/core/manager.py:100:1: F401 'bip_utils.Bip39MnemonicGenerator' imported but unused
./src/seedpass/core/manager.py:100:1: F401 'bip_utils.Bip39Languages' imported but unused
./src/seedpass/core/manager.py:100:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:102:1: F811 redefinition of unused 'datetime' from line 22
./src/seedpass/core/manager.py:137:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:231:80: E501 line too long (101 > 79 characters)
./src/seedpass/core/manager.py:232:80: E501 line too long (103 > 79 characters)
./src/seedpass/core/manager.py:233:80: E501 line too long (93 > 79 characters)
./src/seedpass/core/manager.py:236:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:245:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:320:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:381:80: E501 line too long (92 > 79 characters)
./src/seedpass/core/manager.py:423:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:530:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:548:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:559:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:561:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:563:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:567:80: E501 line too long (120 > 79 characters)
./src/seedpass/core/manager.py:600:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:603:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:617:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:651:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:664:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:678:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:692:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:697:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:714:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:737:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:738:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:739:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:767:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:777:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:785:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:786:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:788:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:841:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:842:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:850:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:908:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:919:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:924:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:937:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:943:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:947:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:966:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:971:80: E501 line too long (93 > 79 characters)
./src/seedpass/core/manager.py:991:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:993:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1012:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:1019:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:1028:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1058:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1064:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1075:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:1083:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1091:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1098:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:1106:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1111:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1113:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1137:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1154:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:1172:80: E501 line too long (105 > 79 characters)
./src/seedpass/core/manager.py:1175:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1180:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1187:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1193:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1201:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1208:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1212:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:1214:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1219:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1221:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1225:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1232:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:1284:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1285:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1288:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1289:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1294:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1301:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1313:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1314:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1335:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1355:80: E501 line too long (90 > 79 characters)
./src/seedpass/core/manager.py:1361:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:1362:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:1363:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1396:80: E501 line too long (114 > 79 characters)
./src/seedpass/core/manager.py:1407:80: E501 line too long (106 > 79 characters)
./src/seedpass/core/manager.py:1423:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1468:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:1469:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:1504:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1510:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:1524:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:1537:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1548:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1564:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1575:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1591:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1598:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1605:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:1611:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1624:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:1648:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:1670:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:1674:13: F841 local variable 'loop' is assigned to but never used
./src/seedpass/core/manager.py:1706:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1709:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/manager.py:1721:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:1729:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1732:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1737:13: F841 local variable 'loop' is assigned to but never used
./src/seedpass/core/manager.py:1785:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1789:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1808:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1816:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:1828:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1835:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1842:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1866:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1878:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1882:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1909:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:1919:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:1932:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1949:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:1958:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1961:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:1969:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1978:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1984:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:1985:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:1991:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:2010:80: E501 line too long (117 > 79 characters)
./src/seedpass/core/manager.py:2019:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:2052:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2068:80: E501 line too long (95 > 79 characters)
./src/seedpass/core/manager.py:2073:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:2111:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2122:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2124:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2129:80: E501 line too long (102 > 79 characters)
./src/seedpass/core/manager.py:2159:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2180:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:2185:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2206:80: E501 line too long (98 > 79 characters)
./src/seedpass/core/manager.py:2211:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:2248:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2257:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:2260:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:2266:80: E501 line too long (113 > 79 characters)
./src/seedpass/core/manager.py:2275:80: E501 line too long (93 > 79 characters)
./src/seedpass/core/manager.py:2313:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2327:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2347:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:2354:80: E501 line too long (114 > 79 characters)
./src/seedpass/core/manager.py:2390:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2399:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:2404:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2413:80: E501 line too long (117 > 79 characters)
./src/seedpass/core/manager.py:2432:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:2459:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:2460:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:2464:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2482:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:2541:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:2572:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:2579:80: E501 line too long (95 > 79 characters)
./src/seedpass/core/manager.py:2584:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:2628:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:2664:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2672:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2687:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:2689:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:2739:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:2767:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:2773:80: E501 line too long (139 > 79 characters)
./src/seedpass/core/manager.py:2788:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:2815:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2816:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2823:80: E501 line too long (95 > 79 characters)
./src/seedpass/core/manager.py:2845:80: E501 line too long (128 > 79 characters)
./src/seedpass/core/manager.py:2853:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:2861:80: E501 line too long (102 > 79 characters)
./src/seedpass/core/manager.py:2866:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:2880:80: E501 line too long (124 > 79 characters)
./src/seedpass/core/manager.py:2890:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2892:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2900:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:2902:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:2903:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:2910:80: E501 line too long (98 > 79 characters)
./src/seedpass/core/manager.py:2931:80: E501 line too long (120 > 79 characters)
./src/seedpass/core/manager.py:2956:80: E501 line too long (117 > 79 characters)
./src/seedpass/core/manager.py:2969:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:2985:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:2992:80: E501 line too long (114 > 79 characters)
./src/seedpass/core/manager.py:3012:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3021:80: E501 line too long (134 > 79 characters)
./src/seedpass/core/manager.py:3026:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3044:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:3049:80: E501 line too long (96 > 79 characters)
./src/seedpass/core/manager.py:3062:80: E501 line too long (124 > 79 characters)
./src/seedpass/core/manager.py:3085:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:3106:80: E501 line too long (138 > 79 characters)
./src/seedpass/core/manager.py:3118:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:3122:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:3144:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3153:80: E501 line too long (136 > 79 characters)
./src/seedpass/core/manager.py:3158:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3194:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3201:80: E501 line too long (95 > 79 characters)
./src/seedpass/core/manager.py:3232:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:3245:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:3250:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3279:80: E501 line too long (97 > 79 characters)
./src/seedpass/core/manager.py:3292:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/manager.py:3299:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3304:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:3309:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:3313:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:3315:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3319:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3350:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:3355:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3360:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:3373:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/manager.py:3380:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3386:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3424:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:3429:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3434:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/manager.py:3439:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:3444:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:3457:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/manager.py:3464:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3469:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:3480:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:3482:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3486:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3518:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:3523:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:3527:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:3534:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:3541:80: E501 line too long (91 > 79 characters)
./src/seedpass/core/manager.py:3547:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3553:80: E501 line too long (97 > 79 characters)
./src/seedpass/core/manager.py:3566:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/manager.py:3573:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3578:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:3583:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:3587:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:3589:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3593:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3616:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3678:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:3708:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3712:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:3743:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3761:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:3767:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3770:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3773:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:3775:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3787:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3806:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:3807:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3814:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3825:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:3826:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:3831:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:3865:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:3879:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:3947:80: E501 line too long (100 > 79 characters)
./src/seedpass/core/manager.py:3974:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:3975:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:3984:80: E501 line too long (96 > 79 characters)
./src/seedpass/core/manager.py:3997:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:4000:80: E501 line too long (126 > 79 characters)
./src/seedpass/core/manager.py:4012:80: E501 line too long (91 > 79 characters)
./src/seedpass/core/manager.py:4018:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:4037:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:4063:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:4066:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:4067:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4072:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4077:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:4081:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:4085:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:4088:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/manager.py:4111:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4160:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4217:80: E501 line too long (100 > 79 characters)
./src/seedpass/core/manager.py:4228:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:4254:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:4267:80: E501 line too long (93 > 79 characters)
./src/seedpass/core/manager.py:4285:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4287:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4319:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4321:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4388:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:4392:80: E501 line too long (101 > 79 characters)
./src/seedpass/core/manager.py:4407:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/manager.py:4417:80: E501 line too long (99 > 79 characters)
./src/seedpass/core/manager.py:4428:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4432:80: E501 line too long (93 > 79 characters)
./src/seedpass/core/manager.py:4434:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4439:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:4447:80: E501 line too long (112 > 79 characters)
./src/seedpass/core/manager.py:4454:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4458:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:4459:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/manager.py:4496:80: E501 line too long (122 > 79 characters)
./src/seedpass/core/manager.py:4508:80: E501 line too long (94 > 79 characters)
./src/seedpass/core/manager.py:4516:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4529:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/manager.py:4534:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4549:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4557:80: E501 line too long (90 > 79 characters)
./src/seedpass/core/manager.py:4560:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:4561:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:4633:80: E501 line too long (97 > 79 characters)
./src/seedpass/core/manager.py:4641:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4659:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4722:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:4725:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/manager.py:4732:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/manager.py:4735:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:4738:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/manager.py:4744:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/manager.py:4749:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/manager.py:4752:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/menu_handler.py:46:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/menu_handler.py:75:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/menu_handler.py:79:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/menu_handler.py:108:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/menu_handler.py:141:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/menu_handler.py:149:80: E501 line too long (108 > 79 characters)
./src/seedpass/core/menu_handler.py:153:80: E501 line too long (109 > 79 characters)
./src/seedpass/core/menu_handler.py:162:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/menu_handler.py:170:80: E501 line too long (108 > 79 characters)
./src/seedpass/core/menu_handler.py:174:80: E501 line too long (104 > 79 characters)
./src/seedpass/core/menu_handler.py:179:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/password_generation.py:6:80: E501 line too long (98 > 79 characters)
./src/seedpass/core/password_generation.py:7:80: E501 line too long (90 > 79 characters)
./src/seedpass/core/password_generation.py:10:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/password_generation.py:12:80: E501 line too long (142 > 79 characters)
./src/seedpass/core/password_generation.py:13:80: E501 line too long (167 > 79 characters)
./src/seedpass/core/password_generation.py:21:1: F401 'os' imported but unused
./src/seedpass/core/password_generation.py:26:1: F401 'base64' imported but unused
./src/seedpass/core/password_generation.py:27:1: F401 'typing.Optional' imported but unused
./src/seedpass/core/password_generation.py:30:1: F401 'pathlib.Path' imported but unused
./src/seedpass/core/password_generation.py:31:1: F401 'shutil' imported but unused
./src/seedpass/core/password_generation.py:73:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/password_generation.py:90:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/password_generation.py:91:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/password_generation.py:103:80: E501 line too long (103 > 79 characters)
./src/seedpass/core/password_generation.py:106:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/password_generation.py:108:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/password_generation.py:119:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/password_generation.py:125:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/password_generation.py:126:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/password_generation.py:131:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/password_generation.py:141:9: F841 local variable 'hkdf_derived' is assigned to but never used
./src/seedpass/core/password_generation.py:155:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/password_generation.py:178:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/password_generation.py:185:80: E501 line too long (95 > 79 characters)
./src/seedpass/core/password_generation.py:206:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/password_generation.py:209:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/password_generation.py:213:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/password_generation.py:216:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/password_generation.py:252:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/password_generation.py:265:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/password_generation.py:279:80: E501 line too long (97 > 79 characters)
./src/seedpass/core/password_generation.py:280:80: E501 line too long (92 > 79 characters)
./src/seedpass/core/password_generation.py:312:80: E501 line too long (146 > 79 characters)
./src/seedpass/core/password_generation.py:337:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/password_generation.py:344:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/password_generation.py:358:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/password_generation.py:363:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/password_generation.py:364:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/password_generation.py:372:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/password_generation.py:374:80: E501 line too long (102 > 79 characters)
./src/seedpass/core/password_generation.py:390:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/password_generation.py:394:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/password_generation.py:406:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/password_generation.py:408:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/password_generation.py:409:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/password_generation.py:414:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/password_generation.py:416:80: E501 line too long (97 > 79 characters)
./src/seedpass/core/password_generation.py:425:80: E501 line too long (136 > 79 characters)
./src/seedpass/core/password_generation.py:431:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/password_generation.py:432:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/password_generation.py:472:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/password_generation.py:516:80: E501 line too long (84 > 79 characters)
./src/seedpass/core/portable_backup.py:57:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/portable_backup.py:110:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/profile_service.py:14:5: F401 'nostr.client.NostrClient' imported but unused
./src/seedpass/core/profile_service.py:23:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/profile_service.py:37:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/profile_service.py:38:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/profile_service.py:39:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/profile_service.py:48:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/profile_service.py:52:80: E501 line too long (95 > 79 characters)
./src/seedpass/core/profile_service.py:71:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/profile_service.py:96:80: E501 line too long (93 > 79 characters)
./src/seedpass/core/profile_service.py:101:80: E501 line too long (86 > 79 characters)
./src/seedpass/core/profile_service.py:107:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/profile_service.py:108:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/pubsub.py:9:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/pubsub.py:21:80: E501 line too long (85 > 79 characters)
./src/seedpass/core/totp.py:45:80: E501 line too long (83 > 79 characters)
./src/seedpass/core/totp.py:71:80: E501 line too long (92 > 79 characters)
./src/seedpass/core/vault.py:70:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/vault.py:84:80: E501 line too long (80 > 79 characters)
./src/seedpass/core/vault.py:92:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/vault.py:93:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/vault.py:98:80: E501 line too long (88 > 79 characters)
./src/seedpass/core/vault.py:105:80: E501 line too long (87 > 79 characters)
./src/seedpass/core/vault.py:132:80: E501 line too long (92 > 79 characters)
./src/seedpass/core/vault.py:150:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/vault.py:172:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/vault.py:184:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/vault.py:199:80: E501 line too long (89 > 79 characters)
./src/seedpass/core/vault.py:210:80: E501 line too long (82 > 79 characters)
./src/seedpass/core/vault.py:222:80: E501 line too long (81 > 79 characters)
./src/seedpass/core/vault.py:260:80: E501 line too long (80 > 79 characters)
./src/seedpass_gui/app.py:34:80: E501 line too long (80 > 79 characters)
./src/seedpass_gui/app.py:93:80: E501 line too long (81 > 79 characters)
./src/seedpass_gui/app.py:252:80: E501 line too long (85 > 79 characters)
./src/seedpass_gui/app.py:451:80: E501 line too long (85 > 79 characters)
./src/tests/conftest.py:10:1: E402 module level import not at top of file
./src/tests/conftest.py:11:1: E402 module level import not at top of file
./src/tests/conftest.py:12:1: E402 module level import not at top of file
./src/tests/conftest.py:13:1: E402 module level import not at top of file
./src/tests/conftest.py:14:1: E402 module level import not at top of file
./src/tests/helpers.py:2:1: F401 'time' imported but unused
./src/tests/helpers.py:8:1: E402 module level import not at top of file
./src/tests/helpers.py:9:1: E402 module level import not at top of file
./src/tests/helpers.py:10:1: E402 module level import not at top of file
./src/tests/helpers.py:14:1: E402 module level import not at top of file
./src/tests/helpers.py:16:80: E501 line too long (107 > 79 characters)
./src/tests/helpers.py:37:1: E402 module level import not at top of file
./src/tests/helpers.py:38:1: F401 'asyncio' imported but unused
./src/tests/helpers.py:38:1: E402 module level import not at top of file
./src/tests/helpers.py:39:1: E402 module level import not at top of file
./src/tests/helpers.py:41:1: E402 module level import not at top of file
./src/tests/helpers.py:49:80: E501 line too long (88 > 79 characters)
./src/tests/helpers.py:228:80: E501 line too long (83 > 79 characters)
./src/tests/helpers.py:258:80: E501 line too long (81 > 79 characters)
./src/tests/test_add_new_fingerprint_words.py:23:80: E501 line too long (87 > 79 characters)
./src/tests/test_add_tags_from_retrieve.py:10:1: E402 module level import not at top of file
./src/tests/test_add_tags_from_retrieve.py:11:1: E402 module level import not at top of file
./src/tests/test_add_tags_from_retrieve.py:12:1: E402 module level import not at top of file
./src/tests/test_add_tags_from_retrieve.py:13:1: E402 module level import not at top of file
./src/tests/test_additional_backup.py:25:80: E501 line too long (83 > 79 characters)
./src/tests/test_additional_backup.py:36:80: E501 line too long (84 > 79 characters)
./src/tests/test_api.py:11:1: E402 module level import not at top of file
./src/tests/test_api.py:12:1: E402 module level import not at top of file
./src/tests/test_api.py:63:80: E501 line too long (82 > 79 characters)
./src/tests/test_api.py:66:80: E501 line too long (81 > 79 characters)
./src/tests/test_api.py:91:80: E501 line too long (81 > 79 characters)
./src/tests/test_api.py:104:80: E501 line too long (81 > 79 characters)
./src/tests/test_api.py:117:80: E501 line too long (81 > 79 characters)
./src/tests/test_api.py:130:80: E501 line too long (81 > 79 characters)
./src/tests/test_api.py:136:80: E501 line too long (82 > 79 characters)
./src/tests/test_api.py:172:80: E501 line too long (82 > 79 characters)
./src/tests/test_api.py:181:80: E501 line too long (81 > 79 characters)
./src/tests/test_api.py:188:80: E501 line too long (83 > 79 characters)
./src/tests/test_api.py:191:80: E501 line too long (82 > 79 characters)
./src/tests/test_api.py:206:80: E501 line too long (87 > 79 characters)
./src/tests/test_api.py:207:80: E501 line too long (82 > 79 characters)
./src/tests/test_api.py:216:80: E501 line too long (81 > 79 characters)
./src/tests/test_api.py:222:80: E501 line too long (82 > 79 characters)
./src/tests/test_api.py:253:80: E501 line too long (81 > 79 characters)
./src/tests/test_api_new_endpoints.py:8:1: F401 'test_api.client' imported but unused
./src/tests/test_api_new_endpoints.py:9:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_api_new_endpoints.py:11:1: F401 'seedpass.core.password_generation.PasswordPolicy' imported but unused
./src/tests/test_api_new_endpoints.py:17:45: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:71:44: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:107:35: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:115:80: E501 line too long (82 > 79 characters)
./src/tests/test_api_new_endpoints.py:121:42: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:141:37: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:143:80: E501 line too long (88 > 79 characters)
./src/tests/test_api_new_endpoints.py:152:36: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:165:80: E501 line too long (82 > 79 characters)
./src/tests/test_api_new_endpoints.py:171:45: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:180:38: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:184:80: E501 line too long (80 > 79 characters)
./src/tests/test_api_new_endpoints.py:188:80: E501 line too long (83 > 79 characters)
./src/tests/test_api_new_endpoints.py:213:35: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:217:80: E501 line too long (86 > 79 characters)
./src/tests/test_api_new_endpoints.py:236:38: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:264:40: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:290:47: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:308:52: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:325:36: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:350:37: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:376:38: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:398:44: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:403:80: E501 line too long (81 > 79 characters)
./src/tests/test_api_new_endpoints.py:429:58: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:447:43: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:447:51: F811 redefinition of unused 'dummy_nostr_client' from line 9
./src/tests/test_api_new_endpoints.py:447:80: E501 line too long (83 > 79 characters)
./src/tests/test_api_new_endpoints.py:468:80: E501 line too long (83 > 79 characters)
./src/tests/test_api_new_endpoints.py:479:80: E501 line too long (83 > 79 characters)
./src/tests/test_api_new_endpoints.py:497:51: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_new_endpoints.py:527:48: F811 redefinition of unused 'client' from line 8
./src/tests/test_api_notifications.py:1:1: F401 'test_api.client' imported but unused
./src/tests/test_api_notifications.py:9:39: F811 redefinition of unused 'client' from line 1
./src/tests/test_api_notifications.py:12:80: E501 line too long (83 > 79 characters)
./src/tests/test_api_notifications.py:13:80: E501 line too long (86 > 79 characters)
./src/tests/test_api_notifications.py:26:52: F811 redefinition of unused 'client' from line 1
./src/tests/test_api_notifications.py:29:80: E501 line too long (83 > 79 characters)
./src/tests/test_api_notifications.py:43:62: F811 redefinition of unused 'client' from line 1
./src/tests/test_api_profile_stats.py:1:1: F401 'test_api.client' imported but unused
./src/tests/test_api_profile_stats.py:6:39: F811 redefinition of unused 'client' from line 1
./src/tests/test_api_profile_stats.py:12:80: E501 line too long (85 > 79 characters)
./src/tests/test_api_rate_limit.py:4:1: F811 redefinition of unused 'importlib' from line 1
./src/tests/test_api_rate_limit.py:24:80: E501 line too long (84 > 79 characters)
./src/tests/test_api_rate_limit.py:27:80: E501 line too long (81 > 79 characters)
./src/tests/test_api_rate_limit.py:37:80: E501 line too long (82 > 79 characters)
./src/tests/test_api_rate_limit.py:46:80: E501 line too long (87 > 79 characters)
./src/tests/test_api_reload_relays.py:21:80: E501 line too long (80 > 79 characters)
./src/tests/test_archive_from_retrieve.py:11:1: E402 module level import not at top of file
./src/tests/test_archive_from_retrieve.py:12:1: E402 module level import not at top of file
./src/tests/test_archive_from_retrieve.py:13:1: E402 module level import not at top of file
./src/tests/test_archive_from_retrieve.py:14:1: E402 module level import not at top of file
./src/tests/test_archive_nonpassword.py:9:1: E402 module level import not at top of file
./src/tests/test_archive_nonpassword.py:10:1: E402 module level import not at top of file
./src/tests/test_archive_nonpassword.py:11:1: E402 module level import not at top of file
./src/tests/test_archive_nonpassword.py:12:1: E402 module level import not at top of file
./src/tests/test_archive_restore.py:7:1: F401 'pytest' imported but unused
./src/tests/test_archive_restore.py:13:1: E402 module level import not at top of file
./src/tests/test_archive_restore.py:14:1: E402 module level import not at top of file
./src/tests/test_archive_restore.py:15:1: E402 module level import not at top of file
./src/tests/test_archive_restore.py:16:1: E402 module level import not at top of file
./src/tests/test_archive_restore.py:17:1: E402 module level import not at top of file
./src/tests/test_atomic_write.py:20:80: E501 line too long (86 > 79 characters)
./src/tests/test_audit_logger.py:8:1: F401 'importlib' imported but unused
./src/tests/test_audit_logger.py:9:1: F401 'pytest' imported but unused
./src/tests/test_audit_logger.py:39:80: E501 line too long (87 > 79 characters)
./src/tests/test_audit_logger.py:44:80: E501 line too long (80 > 79 characters)
./src/tests/test_audit_logger.py:46:80: E501 line too long (87 > 79 characters)
./src/tests/test_audit_logger.py:50:32: E741 ambiguous variable name 'l'
./src/tests/test_auto_sync.py:10:1: E402 module level import not at top of file
./src/tests/test_background_relay_check.py:9:1: E402 module level import not at top of file
./src/tests/test_background_relay_check.py:10:1: E402 module level import not at top of file
./src/tests/test_background_relay_check.py:19:80: E501 line too long (84 > 79 characters)
./src/tests/test_background_sync_always.py:7:1: E402 module level import not at top of file
./src/tests/test_background_sync_always.py:8:1: E402 module level import not at top of file
./src/tests/test_background_sync_always.py:29:80: E501 line too long (82 > 79 characters)
./src/tests/test_background_sync_always.py:30:80: E501 line too long (85 > 79 characters)
./src/tests/test_background_sync_always.py:31:80: E501 line too long (87 > 79 characters)
./src/tests/test_background_sync_always.py:53:80: E501 line too long (84 > 79 characters)
./src/tests/test_background_sync_always.py:54:80: E501 line too long (83 > 79 characters)
./src/tests/test_background_sync_always.py:55:80: E501 line too long (86 > 79 characters)
./src/tests/test_background_sync_always.py:56:80: E501 line too long (82 > 79 characters)
./src/tests/test_backup_restore.py:11:1: E402 module level import not at top of file
./src/tests/test_backup_restore.py:12:1: E402 module level import not at top of file
./src/tests/test_backup_restore.py:104:80: E501 line too long (83 > 79 characters)
./src/tests/test_bip85_init.py:6:1: E402 module level import not at top of file
./src/tests/test_bip85_init.py:7:1: E402 module level import not at top of file
./src/tests/test_bip85_init.py:8:1: E402 module level import not at top of file
./src/tests/test_bip85_init.py:10:80: E501 line too long (127 > 79 characters)
./src/tests/test_bip85_vectors.py:7:1: E402 module level import not at top of file
./src/tests/test_bip85_vectors.py:8:1: E402 module level import not at top of file
./src/tests/test_bip85_vectors.py:12:1: E402 module level import not at top of file
./src/tests/test_bip85_vectors.py:14:80: E501 line too long (127 > 79 characters)
./src/tests/test_bip85_vectors.py:16:80: E501 line too long (87 > 79 characters)
./src/tests/test_bip85_vectors.py:18:80: E501 line too long (175 > 79 characters)
./src/tests/test_bip85_vectors.py:20:80: E501 line too long (86 > 79 characters)
./src/tests/test_bip85_vectors.py:22:80: E501 line too long (85 > 79 characters)
./src/tests/test_checksum_utils.py:3:1: F401 'pathlib.Path' imported but unused
./src/tests/test_cli_clipboard_flag.py:30:80: E501 line too long (82 > 79 characters)
./src/tests/test_cli_clipboard_flag.py:40:80: E501 line too long (80 > 79 characters)
./src/tests/test_cli_core_services.py:3:1: F401 'typer' imported but unused
./src/tests/test_cli_core_services.py:21:80: E501 line too long (87 > 79 characters)
./src/tests/test_cli_core_services.py:50:80: E501 line too long (82 > 79 characters)
./src/tests/test_cli_doc_examples.py:9:1: E402 module level import not at top of file
./src/tests/test_cli_doc_examples.py:10:1: E402 module level import not at top of file
./src/tests/test_cli_doc_examples.py:11:1: E402 module level import not at top of file
./src/tests/test_cli_doc_examples.py:12:1: E402 module level import not at top of file
./src/tests/test_cli_doc_examples.py:13:1: E402 module level import not at top of file
./src/tests/test_cli_doc_examples.py:19:80: E501 line too long (93 > 79 characters)
./src/tests/test_cli_doc_examples.py:25:80: E501 line too long (87 > 79 characters)
./src/tests/test_cli_doc_examples.py:28:80: E501 line too long (118 > 79 characters)
./src/tests/test_cli_doc_examples.py:30:80: E501 line too long (100 > 79 characters)
./src/tests/test_cli_doc_examples.py:55:80: E501 line too long (80 > 79 characters)
./src/tests/test_cli_doc_examples.py:88:80: E501 line too long (86 > 79 characters)
./src/tests/test_cli_doc_examples.py:111:1: E402 module level import not at top of file
./src/tests/test_cli_entry_add_commands.py:7:1: F401 'helpers.TEST_SEED' imported but unused
./src/tests/test_cli_entry_add_commands.py:139:80: E501 line too long (82 > 79 characters)
./src/tests/test_cli_export_import.py:8:1: E402 module level import not at top of file
./src/tests/test_cli_export_import.py:9:1: E402 module level import not at top of file
./src/tests/test_cli_export_import.py:10:1: E402 module level import not at top of file
./src/tests/test_cli_export_import.py:11:1: E402 module level import not at top of file
./src/tests/test_cli_export_import.py:12:1: E402 module level import not at top of file
./src/tests/test_cli_integration.py:26:80: E501 line too long (87 > 79 characters)
./src/tests/test_cli_integration.py:27:80: E501 line too long (85 > 79 characters)
./src/tests/test_cli_integration.py:28:80: E501 line too long (85 > 79 characters)
./src/tests/test_cli_integration.py:30:80: E501 line too long (81 > 79 characters)
./src/tests/test_cli_integration.py:35:80: E501 line too long (85 > 79 characters)
./src/tests/test_cli_integration.py:56:80: E501 line too long (88 > 79 characters)
./src/tests/test_cli_integration.py:61:80: E501 line too long (87 > 79 characters)
./src/tests/test_cli_invalid_input.py:10:1: E402 module level import not at top of file
./src/tests/test_cli_relays.py:41:80: E501 line too long (84 > 79 characters)
./src/tests/test_cli_subcommands.py:7:1: E402 module level import not at top of file
./src/tests/test_cli_subcommands.py:8:1: E402 module level import not at top of file
./src/tests/test_cli_subcommands.py:17:51: E741 ambiguous variable name 'l'
./src/tests/test_cli_subcommands.py:43:80: E501 line too long (86 > 79 characters)
./src/tests/test_cli_subcommands.py:56:80: E501 line too long (82 > 79 characters)
./src/tests/test_cli_subcommands.py:63:80: E501 line too long (86 > 79 characters)
./src/tests/test_cli_subcommands.py:103:80: E501 line too long (82 > 79 characters)
./src/tests/test_cli_subcommands.py:132:80: E501 line too long (86 > 79 characters)
./src/tests/test_cli_toggle_secret_mode.py:1:1: F401 'types' imported but unused
./src/tests/test_cli_toggle_secret_mode.py:31:80: E501 line too long (82 > 79 characters)
./src/tests/test_clipboard_utils.py:10:1: E402 module level import not at top of file
./src/tests/test_clipboard_utils.py:12:1: E402 module level import not at top of file
./src/tests/test_concurrency_stress.py:10:1: E402 module level import not at top of file
./src/tests/test_concurrency_stress.py:11:1: E402 module level import not at top of file
./src/tests/test_concurrency_stress.py:12:1: E402 module level import not at top of file
./src/tests/test_concurrency_stress.py:13:1: E402 module level import not at top of file
./src/tests/test_concurrency_stress.py:14:1: E402 module level import not at top of file
./src/tests/test_concurrency_stress.py:51:80: E501 line too long (82 > 79 characters)
./src/tests/test_config_manager.py:10:1: E402 module level import not at top of file
./src/tests/test_config_manager.py:11:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_config_manager.py:11:1: E402 module level import not at top of file
./src/tests/test_config_manager.py:12:1: E402 module level import not at top of file
./src/tests/test_config_manager.py:13:1: E402 module level import not at top of file
./src/tests/test_config_manager.py:49:1: E402 module level import not at top of file
./src/tests/test_config_manager.py:125:80: E501 line too long (85 > 79 characters)
./src/tests/test_core_api_services.py:4:1: F401 'threading.Lock' imported but unused
./src/tests/test_core_api_services.py:8:1: F401 'seedpass.core.api.VaultExportResponse' imported but unused
./src/tests/test_core_api_services.py:8:1: F401 'seedpass.core.api.UnlockResponse' imported but unused
./src/tests/test_core_api_services.py:8:1: F401 'seedpass.core.api.PasswordPolicyOptions' imported but unused
./src/tests/test_core_api_services.py:8:1: F401 'seedpass.core.api.GeneratePasswordRequest' imported but unused
./src/tests/test_core_api_services.py:8:1: F401 'seedpass.core.api.GeneratePasswordResponse' imported but unused
./src/tests/test_core_api_services.py:8:1: F401 'seedpass.core.api.AddPasswordEntryRequest' imported but unused
./src/tests/test_core_api_services.py:31:1: F401 'seedpass.core.entry_types.EntryType' imported but unused
./src/tests/test_core_api_services.py:92:80: E501 line too long (86 > 79 characters)
./src/tests/test_core_api_services.py:100:80: E501 line too long (83 > 79 characters)
./src/tests/test_core_api_services.py:114:80: E501 line too long (83 > 79 characters)
./src/tests/test_core_api_services.py:141:80: E501 line too long (80 > 79 characters)
./src/tests/test_core_api_services.py:164:80: E501 line too long (88 > 79 characters)
./src/tests/test_core_api_services.py:181:80: E501 line too long (84 > 79 characters)
./src/tests/test_core_api_services.py:189:80: E501 line too long (85 > 79 characters)
./src/tests/test_core_api_services.py:225:80: E501 line too long (83 > 79 characters)
./src/tests/test_core_api_services.py:262:80: E501 line too long (82 > 79 characters)
./src/tests/test_core_api_services.py:267:80: E501 line too long (88 > 79 characters)
./src/tests/test_core_api_services.py:272:80: E501 line too long (87 > 79 characters)
./src/tests/test_core_api_services.py:286:80: E501 line too long (83 > 79 characters)
./src/tests/test_core_api_services.py:418:80: E501 line too long (88 > 79 characters)
./src/tests/test_core_api_services.py:422:80: E501 line too long (84 > 79 characters)
./src/tests/test_core_api_services.py:427:80: E501 line too long (85 > 79 characters)
./src/tests/test_core_api_services.py:453:80: E501 line too long (84 > 79 characters)
./src/tests/test_core_api_services.py:456:80: E501 line too long (86 > 79 characters)
./src/tests/test_core_api_services.py:469:80: E501 line too long (82 > 79 characters)
./src/tests/test_core_api_services.py:489:80: E501 line too long (85 > 79 characters)
./src/tests/test_core_api_services.py:510:80: E501 line too long (80 > 79 characters)
./src/tests/test_core_services.py:1:1: F401 'types' imported but unused
./src/tests/test_core_services.py:4:80: E501 line too long (84 > 79 characters)
./src/tests/test_core_services.py:51:80: E501 line too long (80 > 79 characters)
./src/tests/test_custom_fields_display.py:8:80: E501 line too long (83 > 79 characters)
./src/tests/test_custom_fields_display.py:10:70: E741 ambiguous variable name 'l'
./src/tests/test_custom_fields_display.py:10:80: E501 line too long (80 > 79 characters)
./src/tests/test_decrypt_messages.py:25:80: E501 line too long (81 > 79 characters)
./src/tests/test_decrypt_messages.py:32:80: E501 line too long (84 > 79 characters)
./src/tests/test_decrypt_messages.py:37:80: E501 line too long (85 > 79 characters)
./src/tests/test_decrypt_messages.py:45:80: E501 line too long (81 > 79 characters)
./src/tests/test_decrypt_messages.py:56:80: E501 line too long (81 > 79 characters)
./src/tests/test_default_encryption_mode.py:6:1: E402 module level import not at top of file
./src/tests/test_default_encryption_mode.py:7:1: E402 module level import not at top of file
./src/tests/test_default_encryption_mode.py:9:1: E402 module level import not at top of file
./src/tests/test_default_encryption_mode.py:10:1: E402 module level import not at top of file
./src/tests/test_default_encryption_mode.py:26:80: E501 line too long (80 > 79 characters)
./src/tests/test_delta_merge.py:4:1: F401 'pytest' imported but unused
./src/tests/test_duplicate_seed_profile_creation.py:1:1: F401 'pytest' imported but unused
./src/tests/test_duplicate_seed_profile_creation.py:9:80: E501 line too long (108 > 79 characters)
./src/tests/test_duplicate_seed_profile_creation.py:15:80: E501 line too long (81 > 79 characters)
./src/tests/test_duplicate_seed_profile_creation.py:16:80: E501 line too long (82 > 79 characters)
./src/tests/test_duplicate_seed_profile_creation.py:17:80: E501 line too long (86 > 79 characters)
./src/tests/test_duplicate_seed_profile_creation.py:30:80: E501 line too long (80 > 79 characters)
./src/tests/test_duplicate_seed_profile_creation.py:38:80: E501 line too long (81 > 79 characters)
./src/tests/test_encryption_checksum.py:12:1: E402 module level import not at top of file
./src/tests/test_encryption_checksum.py:13:1: E402 module level import not at top of file
./src/tests/test_encryption_files.py:12:1: E402 module level import not at top of file
./src/tests/test_encryption_validate_seed.py:4:1: F401 'pytest' imported but unused
./src/tests/test_encryption_validate_seed.py:9:1: E402 module level import not at top of file
./src/tests/test_encryption_validate_seed.py:19:80: E501 line too long (107 > 79 characters)
./src/tests/test_encryption_validate_seed.py:27:80: E501 line too long (111 > 79 characters)
./src/tests/test_entries_empty.py:8:1: E402 module level import not at top of file
./src/tests/test_entries_empty.py:9:1: E402 module level import not at top of file
./src/tests/test_entries_empty.py:10:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_entries_empty.py:10:1: E402 module level import not at top of file
./src/tests/test_entries_empty.py:11:1: E402 module level import not at top of file
./src/tests/test_entry_add.py:4:1: F401 'unittest.mock.patch' imported but unused
./src/tests/test_entry_add.py:11:1: E402 module level import not at top of file
./src/tests/test_entry_add.py:12:1: E402 module level import not at top of file
./src/tests/test_entry_add.py:13:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_entry_add.py:13:1: E402 module level import not at top of file
./src/tests/test_entry_add.py:14:1: E402 module level import not at top of file
./src/tests/test_entry_add.py:29:80: E501 line too long (84 > 79 characters)
./src/tests/test_entry_management_checksum_path.py:8:1: E402 module level import not at top of file
./src/tests/test_entry_management_checksum_path.py:9:1: E402 module level import not at top of file
./src/tests/test_entry_management_checksum_path.py:10:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_entry_management_checksum_path.py:10:1: E402 module level import not at top of file
./src/tests/test_entry_management_checksum_path.py:11:1: E402 module level import not at top of file
./src/tests/test_entry_policy_override.py:11:1: E402 module level import not at top of file
./src/tests/test_entry_policy_override.py:12:1: E402 module level import not at top of file
./src/tests/test_entry_policy_override.py:13:1: E402 module level import not at top of file
./src/tests/test_entry_policy_override.py:14:1: E402 module level import not at top of file
./src/tests/test_entry_policy_override.py:15:1: E402 module level import not at top of file
./src/tests/test_entry_policy_override.py:24:80: E501 line too long (88 > 79 characters)
./src/tests/test_export_totp_codes.py:3:1: F401 'tempfile.TemporaryDirectory' imported but unused
./src/tests/test_export_totp_codes.py:11:1: E402 module level import not at top of file
./src/tests/test_export_totp_codes.py:12:1: E402 module level import not at top of file
./src/tests/test_export_totp_codes.py:13:1: E402 module level import not at top of file
./src/tests/test_export_totp_codes.py:14:1: E402 module level import not at top of file
./src/tests/test_export_totp_codes.py:15:1: F401 'seedpass.core.totp.TotpManager' imported but unused
./src/tests/test_export_totp_codes.py:15:1: E402 module level import not at top of file
./src/tests/test_export_totp_codes.py:45:80: E501 line too long (88 > 79 characters)
./src/tests/test_file_lock.py:52:80: E501 line too long (82 > 79 characters)
./src/tests/test_file_locking.py:24:1: E402 module level import not at top of file
./src/tests/test_file_locking.py:27:80: E501 line too long (82 > 79 characters)
./src/tests/test_file_locking.py:38:80: E501 line too long (86 > 79 characters)
./src/tests/test_fingerprint_encryption.py:11:1: E402 module level import not at top of file
./src/tests/test_fingerprint_encryption.py:12:1: E402 module level import not at top of file
./src/tests/test_fingerprint_encryption.py:16:80: E501 line too long (106 > 79 characters)
./src/tests/test_fingerprint_encryption.py:18:80: E501 line too long (85 > 79 characters)
./src/tests/test_fingerprint_manager_utils.py:6:80: E501 line too long (108 > 79 characters)
./src/tests/test_full_sync_roundtrip.py:5:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_full_sync_roundtrip.py:32:30: F811 redefinition of unused 'dummy_nostr_client' from line 5
./src/tests/test_full_sync_roundtrip_new.py:5:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_full_sync_roundtrip_new.py:32:30: F811 redefinition of unused 'dummy_nostr_client' from line 5
./src/tests/test_fuzz_key_derivation.py:8:1: F811 redefinition of unused 'os' from line 1
./src/tests/test_fuzz_key_derivation.py:29:80: E501 line too long (85 > 79 characters)
./src/tests/test_fuzz_key_derivation.py:37:80: E501 line too long (81 > 79 characters)
./src/tests/test_generate_test_profile.py:18:80: E501 line too long (88 > 79 characters)
./src/tests/test_generate_test_profile.py:27:80: E501 line too long (82 > 79 characters)
./src/tests/test_generate_test_profile_sync.py:8:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_generate_test_profile_sync.py:13:80: E501 line too long (84 > 79 characters)
./src/tests/test_generate_test_profile_sync.py:15:80: E501 line too long (87 > 79 characters)
./src/tests/test_generate_test_profile_sync.py:22:50: F811 redefinition of unused 'dummy_nostr_client' from line 8
./src/tests/test_generate_test_profile_sync.py:34:80: E501 line too long (88 > 79 characters)
./src/tests/test_get_entry_summaries_archived_view.py:14:80: E501 line too long (85 > 79 characters)
./src/tests/test_gui_features.py:9:1: E402 module level import not at top of file
./src/tests/test_gui_features.py:10:1: E402 module level import not at top of file
./src/tests/test_gui_features.py:11:1: E402 module level import not at top of file
./src/tests/test_gui_features.py:33:80: E501 line too long (87 > 79 characters)
./src/tests/test_gui_features.py:35:80: E501 line too long (84 > 79 characters)
./src/tests/test_gui_features.py:82:80: E501 line too long (88 > 79 characters)
./src/tests/test_gui_headless.py:37:80: E501 line too long (86 > 79 characters)
./src/tests/test_gui_headless.py:67:80: E501 line too long (81 > 79 characters)
./src/tests/test_gui_headless.py:91:5: F841 local variable 'app' is assigned to but never used
./src/tests/test_gui_headless.py:158:80: E501 line too long (84 > 79 characters)
./src/tests/test_gui_sync.py:12:80: E501 line too long (87 > 79 characters)
./src/tests/test_import.py:4:5: F401 'bip_utils.Bip39SeedGenerator' imported but unused
./src/tests/test_inactivity_lock.py:10:1: E402 module level import not at top of file
./src/tests/test_index_cache.py:22:80: E501 line too long (81 > 79 characters)
./src/tests/test_index_import_export.py:4:1: F401 'pytest' imported but unused
./src/tests/test_index_import_export.py:11:1: E402 module level import not at top of file
./src/tests/test_index_import_export.py:12:1: E402 module level import not at top of file
./src/tests/test_index_import_export.py:13:1: E402 module level import not at top of file
./src/tests/test_index_import_export.py:15:80: E501 line too long (102 > 79 characters)
./src/tests/test_kdf_iteration_fallback.py:21:80: E501 line too long (87 > 79 characters)
./src/tests/test_kdf_iteration_fallback.py:46:80: E501 line too long (86 > 79 characters)
./src/tests/test_kdf_modes.py:6:1: F401 'types.SimpleNamespace' imported but unused
./src/tests/test_kdf_modes.py:19:80: E501 line too long (107 > 79 characters)
./src/tests/test_kdf_modes.py:34:80: E501 line too long (80 > 79 characters)
./src/tests/test_kdf_modes.py:44:80: E501 line too long (80 > 79 characters)
./src/tests/test_kdf_modes.py:90:80: E501 line too long (87 > 79 characters)
./src/tests/test_key_derivation.py:3:1: F811 redefinition of unused 'logging' from line 1
./src/tests/test_key_derivation.py:38:80: E501 line too long (106 > 79 characters)
./src/tests/test_key_derivation.py:46:80: E501 line too long (106 > 79 characters)
./src/tests/test_key_derivation.py:57:80: E501 line too long (87 > 79 characters)
./src/tests/test_key_derivation.py:61:80: E501 line too long (87 > 79 characters)
./src/tests/test_key_hierarchy.py:15:80: E501 line too long (106 > 79 characters)
./src/tests/test_key_manager_helpers.py:1:1: F401 'pytest' imported but unused
./src/tests/test_key_manager_helpers.py:19:80: E501 line too long (84 > 79 characters)
./src/tests/test_key_validation_failures.py:27:80: E501 line too long (82 > 79 characters)
./src/tests/test_key_validation_failures.py:36:80: E501 line too long (85 > 79 characters)
./src/tests/test_key_validation_failures.py:45:80: E501 line too long (80 > 79 characters)
./src/tests/test_key_value_entry.py:9:1: E402 module level import not at top of file
./src/tests/test_key_value_entry.py:10:1: E402 module level import not at top of file
./src/tests/test_key_value_entry.py:11:1: E402 module level import not at top of file
./src/tests/test_last_used_fingerprint.py:8:1: F401 'seedpass.core.manager.EncryptionMode' imported but unused
./src/tests/test_last_used_fingerprint.py:33:80: E501 line too long (85 > 79 characters)
./src/tests/test_last_used_fingerprint.py:41:80: E501 line too long (81 > 79 characters)
./src/tests/test_last_used_fingerprint.py:44:80: E501 line too long (84 > 79 characters)
./src/tests/test_last_used_fingerprint.py:52:80: E501 line too long (83 > 79 characters)
./src/tests/test_legacy_format_exception.py:27:80: E501 line too long (86 > 79 characters)
./src/tests/test_legacy_format_exception.py:38:80: E501 line too long (88 > 79 characters)
./src/tests/test_legacy_migration.py:83:80: E501 line too long (84 > 79 characters)
./src/tests/test_legacy_migration.py:170:80: E501 line too long (85 > 79 characters)
./src/tests/test_legacy_migration.py:179:80: E501 line too long (87 > 79 characters)
./src/tests/test_legacy_migration.py:207:80: E501 line too long (85 > 79 characters)
./src/tests/test_legacy_migration.py:216:80: E501 line too long (88 > 79 characters)
./src/tests/test_legacy_migration.py:223:80: E501 line too long (80 > 79 characters)
./src/tests/test_legacy_migration.py:264:80: E501 line too long (87 > 79 characters)
./src/tests/test_legacy_migration.py:272:80: E501 line too long (84 > 79 characters)
./src/tests/test_legacy_migration.py:298:80: E501 line too long (85 > 79 characters)
./src/tests/test_legacy_migration.py:304:80: E501 line too long (87 > 79 characters)
./src/tests/test_legacy_migration.py:340:80: E501 line too long (85 > 79 characters)
./src/tests/test_legacy_migration_iterations.py:8:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:10:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:11:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:12:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:13:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:17:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:18:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:19:1: E402 module level import not at top of file
./src/tests/test_legacy_migration_iterations.py:23:80: E501 line too long (87 > 79 characters)
./src/tests/test_legacy_migration_iterations.py:25:80: E501 line too long (81 > 79 characters)
./src/tests/test_legacy_migration_iterations.py:56:80: E501 line too long (88 > 79 characters)
./src/tests/test_legacy_migration_iterations.py:69:80: E501 line too long (81 > 79 characters)
./src/tests/test_legacy_migration_prompt.py:17:80: E501 line too long (81 > 79 characters)
./src/tests/test_legacy_migration_prompt.py:34:80: E501 line too long (85 > 79 characters)
./src/tests/test_legacy_migration_prompt.py:50:80: E501 line too long (85 > 79 characters)
./src/tests/test_legacy_migration_prompt.py:53:80: E501 line too long (81 > 79 characters)
./src/tests/test_legacy_migration_second_session.py:33:80: E501 line too long (85 > 79 characters)
./src/tests/test_list_entries_all_types.py:56:80: E501 line too long (107 > 79 characters)
./src/tests/test_list_entries_all_types.py:63:80: E501 line too long (84 > 79 characters)
./src/tests/test_list_entries_all_types.py:69:80: E501 line too long (81 > 79 characters)
./src/tests/test_list_entries_all_types.py:84:80: E501 line too long (81 > 79 characters)
./src/tests/test_list_entries_sort_filter.py:9:1: E402 module level import not at top of file
./src/tests/test_list_entries_sort_filter.py:10:1: E402 module level import not at top of file
./src/tests/test_list_entries_sort_filter.py:11:1: E402 module level import not at top of file
./src/tests/test_list_entries_sort_filter.py:12:1: E402 module level import not at top of file
./src/tests/test_load_global_config.py:6:1: F401 'pytest' imported but unused
./src/tests/test_managed_account.py:12:1: E402 module level import not at top of file
./src/tests/test_managed_account.py:13:1: E402 module level import not at top of file
./src/tests/test_managed_account.py:14:1: E402 module level import not at top of file
./src/tests/test_managed_account.py:59:80: E501 line too long (83 > 79 characters)
./src/tests/test_managed_account.py:72:80: E501 line too long (81 > 79 characters)
./src/tests/test_managed_account_entry.py:12:1: E402 module level import not at top of file
./src/tests/test_managed_account_entry.py:13:1: E402 module level import not at top of file
./src/tests/test_managed_account_entry.py:14:1: E402 module level import not at top of file
./src/tests/test_managed_account_entry.py:15:1: E402 module level import not at top of file
./src/tests/test_managed_account_entry.py:16:1: E402 module level import not at top of file
./src/tests/test_managed_account_entry.py:17:1: E402 module level import not at top of file
./src/tests/test_managed_account_entry.py:88:80: E501 line too long (83 > 79 characters)
./src/tests/test_managed_account_entry.py:101:80: E501 line too long (81 > 79 characters)
./src/tests/test_manager_add_password.py:4:1: F401 'types.SimpleNamespace' imported but unused
./src/tests/test_manager_add_password.py:6:1: F401 'pytest' imported but unused
./src/tests/test_manager_add_password.py:8:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_manager_add_password.py:12:1: E402 module level import not at top of file
./src/tests/test_manager_add_password.py:13:1: E402 module level import not at top of file
./src/tests/test_manager_add_password.py:14:1: E402 module level import not at top of file
./src/tests/test_manager_add_password.py:15:1: E402 module level import not at top of file
./src/tests/test_manager_add_password.py:16:1: E402 module level import not at top of file
./src/tests/test_manager_add_password.py:24:43: F811 redefinition of unused 'dummy_nostr_client' from line 8
./src/tests/test_manager_add_password.py:67:80: E501 line too long (80 > 79 characters)
./src/tests/test_manager_add_password.py:68:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_add_password.py:93:55: F811 redefinition of unused 'dummy_nostr_client' from line 8
./src/tests/test_manager_add_password.py:93:80: E501 line too long (82 > 79 characters)
./src/tests/test_manager_add_password.py:137:80: E501 line too long (80 > 79 characters)
./src/tests/test_manager_add_password.py:138:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_add_password.py:154:54: F811 redefinition of unused 'dummy_nostr_client' from line 8
./src/tests/test_manager_add_password.py:154:80: E501 line too long (81 > 79 characters)
./src/tests/test_manager_add_password.py:187:80: E501 line too long (80 > 79 characters)
./src/tests/test_manager_add_password.py:188:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_add_totp.py:4:1: F401 'types.SimpleNamespace' imported but unused
./src/tests/test_manager_add_totp.py:10:1: E402 module level import not at top of file
./src/tests/test_manager_add_totp.py:11:1: E402 module level import not at top of file
./src/tests/test_manager_add_totp.py:12:1: E402 module level import not at top of file
./src/tests/test_manager_add_totp.py:13:1: E402 module level import not at top of file
./src/tests/test_manager_add_totp.py:54:80: E501 line too long (83 > 79 characters)
./src/tests/test_manager_add_totp.py:56:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_checksum_backup.py:6:1: E402 module level import not at top of file
./src/tests/test_manager_checksum_backup.py:7:1: E402 module level import not at top of file
./src/tests/test_manager_checksum_backup.py:33:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_checksum_backup.py:44:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_checksum_backup.py:54:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_current_notification.py:8:1: F401 'seedpass.core.manager.Notification' imported but unused
./src/tests/test_manager_current_notification.py:8:1: E402 module level import not at top of file
./src/tests/test_manager_current_notification.py:9:1: E402 module level import not at top of file
./src/tests/test_manager_current_notification.py:23:80: E501 line too long (82 > 79 characters)
./src/tests/test_manager_display_totp_codes.py:24:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_display_totp_codes.py:25:80: E501 line too long (88 > 79 characters)
./src/tests/test_manager_display_totp_codes.py:40:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_display_totp_codes.py:48:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_display_totp_codes.py:49:80: E501 line too long (88 > 79 characters)
./src/tests/test_manager_edit_totp.py:9:1: E402 module level import not at top of file
./src/tests/test_manager_edit_totp.py:10:1: E402 module level import not at top of file
./src/tests/test_manager_edit_totp.py:11:1: E402 module level import not at top of file
./src/tests/test_manager_edit_totp.py:12:1: E402 module level import not at top of file
./src/tests/test_manager_edit_totp.py:48:80: E501 line too long (88 > 79 characters)
./src/tests/test_manager_edit_totp.py:52:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_edit_totp.py:53:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_import_database.py:8:1: E402 module level import not at top of file
./src/tests/test_manager_import_database.py:33:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_import_database.py:50:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_list_entries.py:13:1: E402 module level import not at top of file
./src/tests/test_manager_list_entries.py:14:1: E402 module level import not at top of file
./src/tests/test_manager_list_entries.py:15:1: E402 module level import not at top of file
./src/tests/test_manager_list_entries.py:16:1: E402 module level import not at top of file
./src/tests/test_manager_list_entries.py:17:1: E402 module level import not at top of file
./src/tests/test_manager_list_entries.py:78:80: E501 line too long (88 > 79 characters)
./src/tests/test_manager_list_entries.py:82:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_list_entries.py:137:80: E501 line too long (80 > 79 characters)
./src/tests/test_manager_list_entries.py:141:74: E741 ambiguous variable name 'l'
./src/tests/test_manager_list_entries.py:141:80: E501 line too long (87 > 79 characters)
./src/tests/test_manager_list_entries.py:176:80: E501 line too long (86 > 79 characters)
./src/tests/test_manager_list_entries.py:177:80: E501 line too long (81 > 79 characters)
./src/tests/test_manager_list_entries.py:178:80: E501 line too long (81 > 79 characters)
./src/tests/test_manager_list_entries.py:180:70: E741 ambiguous variable name 'l'
./src/tests/test_manager_list_entries.py:180:80: E501 line too long (83 > 79 characters)
./src/tests/test_manager_list_entries.py:182:80: E501 line too long (87 > 79 characters)
./src/tests/test_manager_list_entries.py:298:74: E741 ambiguous variable name 'l'
./src/tests/test_manager_list_entries.py:298:80: E501 line too long (87 > 79 characters)
./src/tests/test_manager_list_entries.py:306:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_list_entries.py:307:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_list_entries.py:309:80: E501 line too long (83 > 79 characters)
./src/tests/test_manager_list_entries.py:315:80: E501 line too long (80 > 79 characters)
./src/tests/test_manager_retrieve_totp.py:9:1: E402 module level import not at top of file
./src/tests/test_manager_retrieve_totp.py:10:1: E402 module level import not at top of file
./src/tests/test_manager_retrieve_totp.py:11:1: F401 'seedpass.core.manager.TotpManager' imported but unused
./src/tests/test_manager_retrieve_totp.py:11:1: E402 module level import not at top of file
./src/tests/test_manager_retrieve_totp.py:12:1: E402 module level import not at top of file
./src/tests/test_manager_retrieve_totp.py:48:80: E501 line too long (88 > 79 characters)
./src/tests/test_manager_retrieve_totp.py:52:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_search_display.py:10:1: E402 module level import not at top of file
./src/tests/test_manager_search_display.py:11:1: E402 module level import not at top of file
./src/tests/test_manager_search_display.py:12:1: E402 module level import not at top of file
./src/tests/test_manager_search_display.py:13:1: E402 module level import not at top of file
./src/tests/test_manager_search_display.py:37:80: E501 line too long (88 > 79 characters)
./src/tests/test_manager_search_display.py:41:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_search_display.py:42:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_seed_setup.py:17:80: E501 line too long (85 > 79 characters)
./src/tests/test_manager_seed_setup.py:35:80: E501 line too long (80 > 79 characters)
./src/tests/test_manager_seed_setup.py:55:80: E501 line too long (80 > 79 characters)
./src/tests/test_manager_warning_notifications.py:8:1: E402 module level import not at top of file
./src/tests/test_manager_warning_notifications.py:9:1: E402 module level import not at top of file
./src/tests/test_manager_warning_notifications.py:10:1: E402 module level import not at top of file
./src/tests/test_manager_warning_notifications.py:11:1: E402 module level import not at top of file
./src/tests/test_manager_warning_notifications.py:12:1: E402 module level import not at top of file
./src/tests/test_manager_warning_notifications.py:37:80: E501 line too long (84 > 79 characters)
./src/tests/test_manager_workflow.py:8:1: E402 module level import not at top of file
./src/tests/test_manager_workflow.py:9:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_manager_workflow.py:9:1: E402 module level import not at top of file
./src/tests/test_manager_workflow.py:10:1: E402 module level import not at top of file
./src/tests/test_manager_workflow.py:11:1: E402 module level import not at top of file
./src/tests/test_manager_workflow.py:12:1: E402 module level import not at top of file
./src/tests/test_manager_workflow.py:37:80: E501 line too long (81 > 79 characters)
./src/tests/test_manager_workflow.py:81:80: E501 line too long (83 > 79 characters)
./src/tests/test_manager_workflow.py:91:80: E501 line too long (83 > 79 characters)
./src/tests/test_manifest_id_privacy.py:3:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_manifest_id_privacy.py:6:42: F811 redefinition of unused 'dummy_nostr_client' from line 3
./src/tests/test_manifest_state_restore.py:1:1: F401 'asyncio' imported but unused
./src/tests/test_manifest_state_restore.py:38:80: E501 line too long (80 > 79 characters)
./src/tests/test_manifest_state_restore.py:51:80: E501 line too long (81 > 79 characters)
./src/tests/test_memory_protection.py:6:1: E402 module level import not at top of file
./src/tests/test_memory_protection.py:8:1: E402 module level import not at top of file
./src/tests/test_menu_navigation.py:9:1: E402 module level import not at top of file
./src/tests/test_menu_navigation.py:46:80: E501 line too long (85 > 79 characters)
./src/tests/test_menu_notifications.py:10:1: E402 module level import not at top of file
./src/tests/test_menu_notifications.py:19:80: E501 line too long (80 > 79 characters)
./src/tests/test_menu_options.py:9:1: E402 module level import not at top of file
./src/tests/test_menu_options.py:48:80: E501 line too long (85 > 79 characters)
./src/tests/test_menu_search.py:9:1: E402 module level import not at top of file
./src/tests/test_migrations.py:8:1: E402 module level import not at top of file
./src/tests/test_migrations.py:36:80: E501 line too long (86 > 79 characters)
./src/tests/test_migrations.py:104:80: E501 line too long (81 > 79 characters)
./src/tests/test_modify_ssh_managed_entries.py:9:1: E402 module level import not at top of file
./src/tests/test_modify_ssh_managed_entries.py:10:1: E402 module level import not at top of file
./src/tests/test_modify_ssh_managed_entries.py:11:1: E402 module level import not at top of file
./src/tests/test_modify_ssh_managed_entries.py:27:80: E501 line too long (82 > 79 characters)
./src/tests/test_multiple_deltas_sync.py:5:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_multiple_deltas_sync.py:32:39: F811 redefinition of unused 'dummy_nostr_client' from line 5
./src/tests/test_multiple_deltas_sync.py:68:47: F811 redefinition of unused 'dummy_nostr_client' from line 5
./src/tests/test_multiple_fingerprint_prompt.py:12:80: E501 line too long (81 > 79 characters)
./src/tests/test_multiple_fingerprint_prompt.py:32:80: E501 line too long (85 > 79 characters)
./src/tests/test_multiple_fingerprint_prompt.py:40:80: E501 line too long (81 > 79 characters)
./src/tests/test_multiple_fingerprint_prompt.py:43:80: E501 line too long (84 > 79 characters)
./src/tests/test_multiple_fingerprint_prompt.py:51:80: E501 line too long (83 > 79 characters)
./src/tests/test_new_seed_profile_creation.py:1:1: F401 'pytest' imported but unused
./src/tests/test_new_seed_profile_creation.py:10:80: E501 line too long (108 > 79 characters)
./src/tests/test_new_seed_profile_creation.py:16:80: E501 line too long (81 > 79 characters)
./src/tests/test_new_seed_profile_creation.py:18:80: E501 line too long (82 > 79 characters)
./src/tests/test_new_seed_profile_creation.py:19:80: E501 line too long (86 > 79 characters)
./src/tests/test_new_seed_profile_creation.py:32:80: E501 line too long (80 > 79 characters)
./src/tests/test_new_seed_profile_creation.py:48:80: E501 line too long (84 > 79 characters)
./src/tests/test_noninteractive_init_unlock.py:37:80: E501 line too long (81 > 79 characters)
./src/tests/test_noninteractive_init_unlock.py:40:80: E501 line too long (84 > 79 characters)
./src/tests/test_noninteractive_init_unlock.py:43:80: E501 line too long (82 > 79 characters)
./src/tests/test_noninteractive_init_unlock.py:46:9: F841 local variable 'pm' is assigned to but never used
./src/tests/test_noninteractive_init_unlock.py:46:80: E501 line too long (83 > 79 characters)
./src/tests/test_noninteractive_init_unlock.py:66:80: E501 line too long (83 > 79 characters)
./src/tests/test_noninteractive_init_unlock.py:76:80: E501 line too long (81 > 79 characters)
./src/tests/test_noninteractive_init_unlock.py:79:80: E501 line too long (84 > 79 characters)
./src/tests/test_nostr_backup.py:10:1: E402 module level import not at top of file
./src/tests/test_nostr_backup.py:11:1: E402 module level import not at top of file
./src/tests/test_nostr_backup.py:12:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_nostr_backup.py:12:1: E402 module level import not at top of file
./src/tests/test_nostr_backup.py:13:1: E402 module level import not at top of file
./src/tests/test_nostr_backup.py:14:1: E402 module level import not at top of file
./src/tests/test_nostr_backup.py:42:80: E501 line too long (80 > 79 characters)
./src/tests/test_nostr_client.py:12:1: E402 module level import not at top of file
./src/tests/test_nostr_client.py:13:1: E402 module level import not at top of file
./src/tests/test_nostr_client.py:14:1: E402 module level import not at top of file
./src/tests/test_nostr_client.py:15:1: F401 'constants' imported but unused
./src/tests/test_nostr_client.py:15:1: E402 module level import not at top of file
./src/tests/test_nostr_client.py:27:13: F841 local variable 'mock_builder' is assigned to but never used
./src/tests/test_nostr_client.py:28:80: E501 line too long (83 > 79 characters)
./src/tests/test_nostr_client.py:83:80: E501 line too long (83 > 79 characters)
./src/tests/test_nostr_client.py:198:80: E501 line too long (84 > 79 characters)
./src/tests/test_nostr_client.py:199:80: E501 line too long (80 > 79 characters)
./src/tests/test_nostr_contract.py:11:1: E402 module level import not at top of file
./src/tests/test_nostr_contract.py:12:1: F401 'nostr.client.Manifest' imported but unused
./src/tests/test_nostr_contract.py:12:1: E402 module level import not at top of file
./src/tests/test_nostr_contract.py:68:80: E501 line too long (80 > 79 characters)
./src/tests/test_nostr_contract.py:70:80: E501 line too long (83 > 79 characters)
./src/tests/test_nostr_dummy_client.py:6:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_nostr_dummy_client.py:12:1: F401 'constants' imported but unused
./src/tests/test_nostr_dummy_client.py:34:40: F811 redefinition of unused 'dummy_nostr_client' from line 6
./src/tests/test_nostr_dummy_client.py:55:35: F811 redefinition of unused 'dummy_nostr_client' from line 6
./src/tests/test_nostr_dummy_client.py:72:51: F811 redefinition of unused 'dummy_nostr_client' from line 6
./src/tests/test_nostr_dummy_client.py:72:80: E501 line too long (83 > 79 characters)
./src/tests/test_nostr_dummy_client.py:74:5: F401 'gzip' imported but unused
./src/tests/test_nostr_dummy_client.py:120:40: F811 redefinition of unused 'dummy_nostr_client' from line 6
./src/tests/test_nostr_dummy_client.py:147:66: F811 redefinition of unused 'dummy_nostr_client' from line 6
./src/tests/test_nostr_dummy_client.py:147:80: E501 line too long (85 > 79 characters)
./src/tests/test_nostr_entry.py:11:1: E402 module level import not at top of file
./src/tests/test_nostr_entry.py:12:1: E402 module level import not at top of file
./src/tests/test_nostr_entry.py:13:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_nostr_entry.py:13:1: E402 module level import not at top of file
./src/tests/test_nostr_entry.py:14:1: E402 module level import not at top of file
./src/tests/test_nostr_index_size.py:14:1: F811 redefinition of unused 'os' from line 1
./src/tests/test_nostr_index_size.py:18:1: E402 module level import not at top of file
./src/tests/test_nostr_index_size.py:19:1: E402 module level import not at top of file
./src/tests/test_nostr_index_size.py:20:1: E402 module level import not at top of file
./src/tests/test_nostr_index_size.py:21:1: E402 module level import not at top of file
./src/tests/test_nostr_index_size.py:22:1: E402 module level import not at top of file
./src/tests/test_nostr_index_size.py:23:1: E402 module level import not at top of file
./src/tests/test_nostr_index_size.py:59:80: E501 line too long (82 > 79 characters)
./src/tests/test_nostr_index_size.py:74:80: E501 line too long (88 > 79 characters)
./src/tests/test_nostr_index_size.py:80:80: E501 line too long (84 > 79 characters)
./src/tests/test_nostr_index_size.py:88:80: E501 line too long (84 > 79 characters)
./src/tests/test_nostr_index_size.py:91:80: E501 line too long (83 > 79 characters)
./src/tests/test_nostr_legacy_decrypt_fallback.py:17:80: E501 line too long (84 > 79 characters)
./src/tests/test_nostr_legacy_key_fallback.py:6:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_nostr_legacy_key_fallback.py:11:45: F811 redefinition of unused 'dummy_nostr_client' from line 6
./src/tests/test_nostr_legacy_key_fallback.py:29:80: E501 line too long (86 > 79 characters)
./src/tests/test_nostr_qr.py:9:1: E402 module level import not at top of file
./src/tests/test_nostr_qr.py:10:1: E402 module level import not at top of file
./src/tests/test_nostr_qr.py:11:1: F401 'seedpass.core.manager.TotpManager' imported but unused
./src/tests/test_nostr_qr.py:11:1: E402 module level import not at top of file
./src/tests/test_nostr_qr.py:12:1: E402 module level import not at top of file
./src/tests/test_nostr_qr.py:13:1: E402 module level import not at top of file
./src/tests/test_nostr_real.py:16:1: E402 module level import not at top of file
./src/tests/test_nostr_real.py:17:1: E402 module level import not at top of file
./src/tests/test_nostr_real.py:41:80: E501 line too long (80 > 79 characters)
./src/tests/test_nostr_restore_flow.py:32:80: E501 line too long (81 > 79 characters)
./src/tests/test_nostr_sdk_workflow.py:45:80: E501 line too long (106 > 79 characters)
./src/tests/test_nostr_snapshot.py:92:80: E501 line too long (87 > 79 characters)
./src/tests/test_nostr_snapshot.py:99:80: E501 line too long (84 > 79 characters)
./src/tests/test_offline_mode_profile_creation.py:4:1: F401 'pytest' imported but unused
./src/tests/test_parent_seed_backup.py:9:1: E402 module level import not at top of file
./src/tests/test_parent_seed_backup.py:10:1: F401 'constants.DEFAULT_SEED_BACKUP_FILENAME' imported but unused
./src/tests/test_parent_seed_backup.py:10:1: E402 module level import not at top of file
./src/tests/test_parent_seed_backup.py:18:80: E501 line too long (87 > 79 characters)
./src/tests/test_parent_seed_backup.py:24:80: E501 line too long (81 > 79 characters)
./src/tests/test_parent_seed_backup.py:29:80: E501 line too long (80 > 79 characters)
./src/tests/test_parent_seed_backup.py:47:80: E501 line too long (80 > 79 characters)
./src/tests/test_parent_seed_backup.py:50:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_change.py:11:1: E402 module level import not at top of file
./src/tests/test_password_change.py:12:1: E402 module level import not at top of file
./src/tests/test_password_change.py:13:1: E402 module level import not at top of file
./src/tests/test_password_change.py:14:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_password_change.py:14:1: E402 module level import not at top of file
./src/tests/test_password_change.py:15:1: E402 module level import not at top of file
./src/tests/test_password_change.py:42:80: E501 line too long (83 > 79 characters)
./src/tests/test_password_generation_policy.py:7:1: E402 module level import not at top of file
./src/tests/test_password_generation_policy.py:16:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_helpers.py:11:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_length_constraints.py:7:1: E402 module level import not at top of file
./src/tests/test_password_length_constraints.py:8:1: E402 module level import not at top of file
./src/tests/test_password_length_constraints.py:17:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_notes_display.py:10:1: E402 module level import not at top of file
./src/tests/test_password_notes_display.py:11:1: E402 module level import not at top of file
./src/tests/test_password_notes_display.py:12:1: E402 module level import not at top of file
./src/tests/test_password_notes_display.py:13:1: E402 module level import not at top of file
./src/tests/test_password_notes_display.py:30:74: E741 ambiguous variable name 'l'
./src/tests/test_password_notes_display.py:30:80: E501 line too long (84 > 79 characters)
./src/tests/test_password_notes_display.py:39:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_notes_display.py:41:80: E501 line too long (80 > 79 characters)
./src/tests/test_password_prompt.py:4:1: F401 'pytest' imported but unused
./src/tests/test_password_prompt.py:12:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_prompt.py:19:80: E501 line too long (82 > 79 characters)
./src/tests/test_password_prompt.py:27:80: E501 line too long (85 > 79 characters)
./src/tests/test_password_properties.py:8:1: E402 module level import not at top of file
./src/tests/test_password_properties.py:9:1: E402 module level import not at top of file
./src/tests/test_password_properties.py:18:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_shuffle_consistency.py:6:1: E402 module level import not at top of file
./src/tests/test_password_shuffle_consistency.py:15:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_special_chars.py:7:1: E402 module level import not at top of file
./src/tests/test_password_special_chars.py:9:1: E402 module level import not at top of file
./src/tests/test_password_special_chars.py:18:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_special_modes.py:7:1: E402 module level import not at top of file
./src/tests/test_password_special_modes.py:8:1: E402 module level import not at top of file
./src/tests/test_password_special_modes.py:17:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_unlock_after_change.py:10:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:11:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:12:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:13:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:14:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:15:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:16:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:17:1: E402 module level import not at top of file
./src/tests/test_password_unlock_after_change.py:19:80: E501 line too long (102 > 79 characters)
./src/tests/test_password_unlock_after_change.py:70:80: E501 line too long (88 > 79 characters)
./src/tests/test_password_unlock_after_change.py:84:80: E501 line too long (83 > 79 characters)
./src/tests/test_password_unlock_after_change.py:85:80: E501 line too long (86 > 79 characters)
./src/tests/test_password_unlock_after_change.py:86:80: E501 line too long (88 > 79 characters)
./src/tests/test_pgp_entry.py:9:1: E402 module level import not at top of file
./src/tests/test_pgp_entry.py:10:1: E402 module level import not at top of file
./src/tests/test_pgp_entry.py:11:1: E402 module level import not at top of file
./src/tests/test_pgp_entry.py:54:80: E501 line too long (85 > 79 characters)
./src/tests/test_portable_backup.py:12:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:13:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:14:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:15:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:16:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:17:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:18:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:19:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:20:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:22:80: E501 line too long (102 > 79 characters)
./src/tests/test_portable_backup.py:73:1: E402 module level import not at top of file
./src/tests/test_portable_backup.py:91:80: E501 line too long (80 > 79 characters)
./src/tests/test_portable_backup.py:143:80: E501 line too long (81 > 79 characters)
./src/tests/test_post_sync_messages.py:7:1: E402 module level import not at top of file
./src/tests/test_profile_cleanup.py:21:80: E501 line too long (81 > 79 characters)
./src/tests/test_profile_cleanup.py:43:80: E501 line too long (83 > 79 characters)
./src/tests/test_profile_deletion_sync.py:9:1: E402 module level import not at top of file
./src/tests/test_profile_deletion_sync.py:10:1: E402 module level import not at top of file
./src/tests/test_profile_deletion_sync.py:11:1: E402 module level import not at top of file
./src/tests/test_profile_export_import.py:1:1: F401 'pathlib.Path' imported but unused
./src/tests/test_profile_init_integration.py:11:80: E501 line too long (84 > 79 characters)
./src/tests/test_profile_init_integration.py:13:80: E501 line too long (87 > 79 characters)
./src/tests/test_profile_init_integration.py:27:80: E501 line too long (83 > 79 characters)
./src/tests/test_profile_init_integration.py:39:80: E501 line too long (83 > 79 characters)
./src/tests/test_profile_init_integration.py:40:80: E501 line too long (86 > 79 characters)
./src/tests/test_profile_management.py:12:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:13:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:14:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:15:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_profile_management.py:15:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:16:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:17:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:18:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:19:1: E402 module level import not at top of file
./src/tests/test_profile_management.py:30:80: E501 line too long (83 > 79 characters)
./src/tests/test_profile_management.py:41:80: E501 line too long (84 > 79 characters)
./src/tests/test_profile_management.py:43:80: E501 line too long (85 > 79 characters)
./src/tests/test_profile_management.py:55:80: E501 line too long (80 > 79 characters)
./src/tests/test_profiles.py:7:1: E402 module level import not at top of file
./src/tests/test_profiles.py:8:1: E402 module level import not at top of file
./src/tests/test_profiles.py:9:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_profiles.py:9:1: E402 module level import not at top of file
./src/tests/test_profiles.py:10:1: E402 module level import not at top of file
./src/tests/test_profiles.py:11:1: E402 module level import not at top of file
./src/tests/test_profiles.py:13:80: E501 line too long (108 > 79 characters)
./src/tests/test_profiles.py:39:80: E501 line too long (86 > 79 characters)
./src/tests/test_profiles.py:40:80: E501 line too long (83 > 79 characters)
./src/tests/test_profiles.py:41:80: E501 line too long (86 > 79 characters)
./src/tests/test_profiles.py:43:80: E501 line too long (82 > 79 characters)
./src/tests/test_profiles.py:55:51: F811 redefinition of unused 'dummy_nostr_client' from line 9
./src/tests/test_profiles.py:86:60: F811 redefinition of unused 'dummy_nostr_client' from line 9
./src/tests/test_publish_json_result.py:12:1: E402 module level import not at top of file
./src/tests/test_publish_json_result.py:13:1: E402 module level import not at top of file
./src/tests/test_publish_json_result.py:22:80: E501 line too long (83 > 79 characters)
./src/tests/test_publish_json_result.py:85:80: E501 line too long (88 > 79 characters)
./src/tests/test_publish_json_result.py:86:80: E501 line too long (82 > 79 characters)
./src/tests/test_quick_unlock_default.py:6:1: F401 'pytest' imported but unused
./src/tests/test_quick_unlock_default.py:10:1: E402 module level import not at top of file
./src/tests/test_quick_unlock_default.py:11:1: E402 module level import not at top of file
./src/tests/test_quick_unlock_default.py:12:1: E402 module level import not at top of file
./src/tests/test_quick_unlock_default.py:34:80: E501 line too long (87 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:31:80: E501 line too long (81 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:32:80: E501 line too long (82 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:65:80: E501 line too long (83 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:77:80: E501 line too long (88 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:119:80: E501 line too long (83 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:137:80: E501 line too long (82 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:144:80: E501 line too long (80 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:154:80: E501 line too long (82 > 79 characters)
./src/tests/test_restore_from_nostr_setup.py:167:80: E501 line too long (81 > 79 characters)
./src/tests/test_retrieve_pause_sensitive_entries.py:8:1: E402 module level import not at top of file
./src/tests/test_search_entries.py:9:1: E402 module level import not at top of file
./src/tests/test_search_entries.py:10:1: E402 module level import not at top of file
./src/tests/test_search_entries.py:11:1: E402 module level import not at top of file
./src/tests/test_search_entries.py:12:1: E402 module level import not at top of file
./src/tests/test_search_entries.py:31:80: E501 line too long (88 > 79 characters)
./src/tests/test_search_entries.py:43:80: E501 line too long (83 > 79 characters)
./src/tests/test_search_entries.py:56:80: E501 line too long (83 > 79 characters)
./src/tests/test_search_entries.py:65:9: F841 local variable 'idx_pw' is assigned to but never used
./src/tests/test_search_entries.py:87:9: F841 local variable 'idx' is assigned to but never used
./src/tests/test_search_entries.py:98:9: F841 local variable 'idx' is assigned to but never used
./src/tests/test_search_entries.py:122:80: E501 line too long (81 > 79 characters)
./src/tests/test_search_entries.py:134:80: E501 line too long (81 > 79 characters)
./src/tests/test_search_entries.py:151:80: E501 line too long (80 > 79 characters)
./src/tests/test_secret_mode.py:11:1: E402 module level import not at top of file
./src/tests/test_secret_mode.py:12:1: E402 module level import not at top of file
./src/tests/test_secret_mode.py:13:1: E402 module level import not at top of file
./src/tests/test_secret_mode.py:14:1: E402 module level import not at top of file
./src/tests/test_secret_mode.py:28:70: E741 ambiguous variable name 'l'
./src/tests/test_secret_mode.py:28:80: E501 line too long (80 > 79 characters)
./src/tests/test_secret_mode.py:65:80: E501 line too long (88 > 79 characters)
./src/tests/test_secret_mode.py:115:80: E501 line too long (88 > 79 characters)
./src/tests/test_secret_mode_profile_creation.py:3:1: F401 'types.SimpleNamespace' imported but unused
./src/tests/test_secret_mode_profile_creation.py:5:1: F401 'pytest' imported but unused
./src/tests/test_seed_entry.py:10:1: E402 module level import not at top of file
./src/tests/test_seed_entry.py:11:1: E402 module level import not at top of file
./src/tests/test_seed_entry.py:12:1: E402 module level import not at top of file
./src/tests/test_seed_entry.py:13:1: E402 module level import not at top of file
./src/tests/test_seed_entry.py:14:1: E402 module level import not at top of file
./src/tests/test_seed_entry.py:15:1: E402 module level import not at top of file
./src/tests/test_seed_generation.py:11:80: E501 line too long (89 > 79 characters)
./src/tests/test_seed_generation.py:21:80: E501 line too long (81 > 79 characters)
./src/tests/test_seed_import.py:11:1: E402 module level import not at top of file
./src/tests/test_seed_import.py:12:1: E402 module level import not at top of file
./src/tests/test_seed_migration.py:13:1: E402 module level import not at top of file
./src/tests/test_seed_prompt.py:20:80: E501 line too long (82 > 79 characters)
./src/tests/test_seed_prompt.py:61:80: E501 line too long (84 > 79 characters)
./src/tests/test_seed_prompt.py:89:80: E501 line too long (80 > 79 characters)
./src/tests/test_seed_word_by_word_flow.py:52:80: E501 line too long (80 > 79 characters)
./src/tests/test_seed_word_by_word_flow.py:85:80: E501 line too long (80 > 79 characters)
./src/tests/test_seedqr_encoding.py:6:1: E402 module level import not at top of file
./src/tests/test_service_classes.py:5:1: F401 'pytest' imported but unused
./src/tests/test_service_classes.py:7:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_service_classes.py:43:50: F811 redefinition of unused 'dummy_nostr_client' from line 7
./src/tests/test_service_classes.py:69:80: E501 line too long (86 > 79 characters)
./src/tests/test_service_classes.py:70:80: E501 line too long (84 > 79 characters)
./src/tests/test_service_classes.py:128:80: E501 line too long (81 > 79 characters)
./src/tests/test_settings_menu.py:16:1: E402 module level import not at top of file
./src/tests/test_settings_menu.py:17:1: E402 module level import not at top of file
./src/tests/test_settings_menu.py:18:1: E402 module level import not at top of file
./src/tests/test_settings_menu.py:19:1: E402 module level import not at top of file
./src/tests/test_settings_menu.py:20:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_settings_menu.py:20:1: E402 module level import not at top of file
./src/tests/test_settings_menu.py:21:1: E402 module level import not at top of file
./src/tests/test_settings_menu.py:60:80: E501 line too long (107 > 79 characters)
./src/tests/test_settings_menu.py:63:80: E501 line too long (89 > 79 characters)
./src/tests/test_settings_menu.py:116:80: E501 line too long (81 > 79 characters)
./src/tests/test_settings_menu.py:136:80: E501 line too long (81 > 79 characters)
./src/tests/test_settings_menu.py:153:80: E501 line too long (88 > 79 characters)
./src/tests/test_settings_menu.py:161:80: E501 line too long (82 > 79 characters)
./src/tests/test_ssh_entry.py:9:1: E402 module level import not at top of file
./src/tests/test_ssh_entry.py:10:1: E402 module level import not at top of file
./src/tests/test_ssh_entry.py:11:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_ssh_entry.py:11:1: E402 module level import not at top of file
./src/tests/test_ssh_entry.py:12:1: E402 module level import not at top of file
./src/tests/test_ssh_entry_valid.py:9:1: E402 module level import not at top of file
./src/tests/test_ssh_entry_valid.py:10:1: E402 module level import not at top of file
./src/tests/test_ssh_entry_valid.py:11:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_ssh_entry_valid.py:11:1: E402 module level import not at top of file
./src/tests/test_ssh_entry_valid.py:12:1: E402 module level import not at top of file
./src/tests/test_ssh_entry_valid.py:13:1: E402 module level import not at top of file
./src/tests/test_stats_screen.py:4:1: F401 'pytest' imported but unused
./src/tests/test_stats_screen.py:9:1: E402 module level import not at top of file
./src/tests/test_stats_screen.py:50:80: E501 line too long (85 > 79 characters)
./src/tests/test_sync_race_conditions.py:35:80: E501 line too long (82 > 79 characters)
./src/tests/test_tag_persistence.py:9:1: E402 module level import not at top of file
./src/tests/test_tag_persistence.py:10:1: E402 module level import not at top of file
./src/tests/test_tag_persistence.py:11:1: E402 module level import not at top of file
./src/tests/test_tag_persistence.py:12:1: E402 module level import not at top of file
./src/tests/test_totp.py:9:1: E402 module level import not at top of file
./src/tests/test_totp.py:10:1: E402 module level import not at top of file
./src/tests/test_totp.py:28:80: E501 line too long (83 > 79 characters)
./src/tests/test_totp_entry.py:4:1: F401 'unittest.mock.patch' imported but unused
./src/tests/test_totp_entry.py:6:1: F401 'pytest' imported but unused
./src/tests/test_totp_entry.py:12:1: E402 module level import not at top of file
./src/tests/test_totp_entry.py:13:1: E402 module level import not at top of file
./src/tests/test_totp_entry.py:14:1: F401 'seedpass.core.vault.Vault' imported but unused
./src/tests/test_totp_entry.py:14:1: E402 module level import not at top of file
./src/tests/test_totp_entry.py:15:1: E402 module level import not at top of file
./src/tests/test_totp_entry.py:16:1: E402 module level import not at top of file
./src/tests/test_totp_entry.py:17:1: E402 module level import not at top of file
./src/tests/test_totp_entry.py:101:80: E501 line too long (86 > 79 characters)
./src/tests/test_totp_uri.py:8:1: E402 module level import not at top of file
./src/tests/test_typer_cli.py:7:1: E402 module level import not at top of file
./src/tests/test_typer_cli.py:9:1: E402 module level import not at top of file
./src/tests/test_typer_cli.py:10:1: E402 module level import not at top of file
./src/tests/test_typer_cli.py:11:1: E402 module level import not at top of file
./src/tests/test_typer_cli.py:12:1: E402 module level import not at top of file
./src/tests/test_typer_cli.py:13:1: E402 module level import not at top of file
./src/tests/test_typer_cli.py:21:80: E501 line too long (81 > 79 characters)
./src/tests/test_typer_cli.py:62:69: E741 ambiguous variable name 'l'
./src/tests/test_typer_cli.py:62:80: E501 line too long (80 > 79 characters)
./src/tests/test_typer_cli.py:79:80: E501 line too long (82 > 79 characters)
./src/tests/test_typer_cli.py:80:80: E501 line too long (81 > 79 characters)
./src/tests/test_typer_cli.py:94:80: E501 line too long (82 > 79 characters)
./src/tests/test_typer_cli.py:95:80: E501 line too long (81 > 79 characters)
./src/tests/test_typer_cli.py:113:80: E501 line too long (82 > 79 characters)
./src/tests/test_typer_cli.py:115:80: E501 line too long (85 > 79 characters)
./src/tests/test_typer_cli.py:131:80: E501 line too long (87 > 79 characters)
./src/tests/test_typer_cli.py:133:80: E501 line too long (86 > 79 characters)
./src/tests/test_typer_cli.py:187:80: E501 line too long (83 > 79 characters)
./src/tests/test_typer_cli.py:215:80: E501 line too long (82 > 79 characters)
./src/tests/test_typer_cli.py:323:80: E501 line too long (83 > 79 characters)
./src/tests/test_typer_cli.py:398:80: E501 line too long (86 > 79 characters)
./src/tests/test_typer_cli.py:412:80: E501 line too long (81 > 79 characters)
./src/tests/test_typer_cli.py:481:80: E501 line too long (82 > 79 characters)
./src/tests/test_typer_cli.py:491:80: E501 line too long (80 > 79 characters)
./src/tests/test_typer_cli.py:506:80: E501 line too long (80 > 79 characters)
./src/tests/test_typer_cli.py:599:80: E501 line too long (80 > 79 characters)
./src/tests/test_unlock_sync.py:10:1: E402 module level import not at top of file
./src/tests/test_unlock_sync.py:11:1: E402 module level import not at top of file
./src/tests/test_unlock_sync.py:26:80: E501 line too long (82 > 79 characters)
./src/tests/test_unlock_sync.py:45:80: E501 line too long (83 > 79 characters)
./src/tests/test_unlock_sync.py:75:80: E501 line too long (84 > 79 characters)
./src/tests/test_unlock_sync.py:76:80: E501 line too long (82 > 79 characters)
./src/tests/test_vault_initialization.py:4:1: F401 'unittest.mock.patch' imported but unused
./src/tests/test_vault_initialization.py:8:1: E402 module level import not at top of file
./src/tests/test_vault_initialization.py:9:1: E402 module level import not at top of file
./src/tests/test_vault_initialization.py:11:80: E501 line too long (108 > 79 characters)
./src/tests/test_vault_initialization.py:23:80: E501 line too long (86 > 79 characters)
./src/tests/test_verbose_timing.py:5:1: F401 'helpers.dummy_nostr_client' imported but unused
./src/tests/test_verbose_timing.py:18:80: E501 line too long (87 > 79 characters)
./src/tests/test_verbose_timing.py:23:37: F811 redefinition of unused 'dummy_nostr_client' from line 5
./src/utils/__init__.py:9:1: E402 module level import not at top of file
./src/utils/__init__.py:10:1: E402 module level import not at top of file
./src/utils/__init__.py:19:1: E402 module level import not at top of file
./src/utils/__init__.py:27:1: E402 module level import not at top of file
./src/utils/__init__.py:28:1: E402 module level import not at top of file
./src/utils/__init__.py:29:1: E402 module level import not at top of file
./src/utils/__init__.py:30:1: E402 module level import not at top of file
./src/utils/__init__.py:31:1: E402 module level import not at top of file
./src/utils/__init__.py:37:1: E402 module level import not at top of file
./src/utils/__init__.py:42:80: E501 line too long (81 > 79 characters)
./src/utils/checksum.py:6:80: E501 line too long (89 > 79 characters)
./src/utils/checksum.py:7:80: E501 line too long (85 > 79 characters)
./src/utils/checksum.py:10:80: E501 line too long (87 > 79 characters)
./src/utils/checksum.py:15:1: F401 'sys' imported but unused
./src/utils/checksum.py:16:1: F401 'os' imported but unused
./src/utils/checksum.py:22:1: F401 'constants.APP_DIR' imported but unused
./src/utils/checksum.py:22:1: F401 'constants.SCRIPT_CHECKSUM_FILE' imported but unused
./src/utils/checksum.py:48:80: E501 line too long (82 > 79 characters)
./src/utils/checksum.py:59:80: E501 line too long (80 > 79 characters)
./src/utils/checksum.py:62:80: E501 line too long (87 > 79 characters)
./src/utils/checksum.py:72:80: E501 line too long (84 > 79 characters)
./src/utils/checksum.py:97:80: E501 line too long (85 > 79 characters)
./src/utils/checksum.py:102:80: E501 line too long (82 > 79 characters)
./src/utils/checksum.py:125:80: E501 line too long (88 > 79 characters)
./src/utils/checksum.py:129:80: E501 line too long (87 > 79 characters)
./src/utils/checksum.py:133:80: E501 line too long (84 > 79 characters)
./src/utils/checksum.py:140:80: E501 line too long (80 > 79 characters)
./src/utils/checksum.py:142:80: E501 line too long (92 > 79 characters)
./src/utils/checksum.py:156:80: E501 line too long (83 > 79 characters)
./src/utils/checksum.py:160:80: E501 line too long (81 > 79 characters)
./src/utils/checksum.py:167:80: E501 line too long (80 > 79 characters)
./src/utils/checksum.py:183:80: E501 line too long (89 > 79 characters)
./src/utils/checksum.py:194:80: E501 line too long (89 > 79 characters)
./src/utils/checksum.py:202:80: E501 line too long (83 > 79 characters)
./src/utils/checksum.py:209:80: E501 line too long (92 > 79 characters)
./src/utils/checksum.py:219:80: E501 line too long (87 > 79 characters)
./src/utils/clipboard.py:19:80: E501 line too long (82 > 79 characters)
./src/utils/clipboard.py:27:80: E501 line too long (85 > 79 characters)
./src/utils/clipboard.py:30:80: E501 line too long (86 > 79 characters)
./src/utils/clipboard.py:36:80: E501 line too long (86 > 79 characters)
./src/utils/file_lock.py:1:80: E501 line too long (80 > 79 characters)
./src/utils/fingerprint.py:6:80: E501 line too long (83 > 79 characters)
./src/utils/fingerprint.py:7:80: E501 line too long (80 > 79 characters)
./src/utils/fingerprint.py:36:80: E501 line too long (81 > 79 characters)
./src/utils/fingerprint_manager.py:3:1: F401 'os' imported but unused
./src/utils/fingerprint_manager.py:23:80: E501 line too long (82 > 79 characters)
./src/utils/fingerprint_manager.py:48:80: E501 line too long (89 > 79 characters)
./src/utils/fingerprint_manager.py:65:80: E501 line too long (80 > 79 characters)
./src/utils/fingerprint_manager.py:69:80: E501 line too long (84 > 79 characters)
./src/utils/fingerprint_manager.py:70:80: E501 line too long (86 > 79 characters)
./src/utils/fingerprint_manager.py:79:80: E501 line too long (81 > 79 characters)
./src/utils/fingerprint_manager.py:83:80: E501 line too long (83 > 79 characters)
./src/utils/fingerprint_manager.py:105:80: E501 line too long (98 > 79 characters)
./src/utils/fingerprint_manager.py:142:80: E501 line too long (84 > 79 characters)
./src/utils/fingerprint_manager.py:178:80: E501 line too long (85 > 79 characters)
./src/utils/fingerprint_manager.py:242:80: E501 line too long (81 > 79 characters)
./src/utils/fingerprint_manager.py:248:80: E501 line too long (84 > 79 characters)
./src/utils/imghdr_stub.py:103:80: E501 line too long (82 > 79 characters)
./src/utils/imghdr_stub.py:112:80: E501 line too long (82 > 79 characters)
./src/utils/imghdr_stub.py:121:80: E501 line too long (82 > 79 characters)
./src/utils/imghdr_stub.py:195:80: E501 line too long (81 > 79 characters)
./src/utils/key_derivation.py:24:1: F401 'typing.Optional' imported but unused
./src/utils/key_derivation.py:78:80: E501 line too long (99 > 79 characters)
./src/utils/key_derivation.py:80:80: E501 line too long (97 > 79 characters)
./src/utils/key_derivation.py:81:80: E501 line too long (99 > 79 characters)
./src/utils/key_derivation.py:87:80: E501 line too long (82 > 79 characters)
./src/utils/key_derivation.py:101:80: E501 line too long (82 > 79 characters)
./src/utils/key_derivation.py:151:80: E501 line too long (80 > 79 characters)
./src/utils/key_derivation.py:172:80: E501 line too long (84 > 79 characters)
./src/utils/key_derivation.py:175:80: E501 line too long (86 > 79 characters)
./src/utils/key_derivation.py:178:80: E501 line too long (86 > 79 characters)
./src/utils/key_derivation.py:188:80: E501 line too long (87 > 79 characters)
./src/utils/key_derivation.py:205:80: E501 line too long (85 > 79 characters)
./src/utils/key_derivation.py:240:80: E501 line too long (85 > 79 characters)
./src/utils/key_derivation.py:266:80: E501 line too long (80 > 79 characters)
./src/utils/key_derivation.py:286:80: E501 line too long (80 > 79 characters)
./src/utils/key_derivation.py:297:80: E501 line too long (86 > 79 characters)
./src/utils/key_validation.py:26:80: E501 line too long (83 > 79 characters)
./src/utils/password_prompt.py:6:80: E501 line too long (94 > 79 characters)
./src/utils/password_prompt.py:7:80: E501 line too long (90 > 79 characters)
./src/utils/password_prompt.py:8:80: E501 line too long (94 > 79 characters)
./src/utils/password_prompt.py:9:80: E501 line too long (86 > 79 characters)
./src/utils/password_prompt.py:11:80: E501 line too long (87 > 79 characters)
./src/utils/password_prompt.py:17:1: F401 'sys' imported but unused
./src/utils/password_prompt.py:39:80: E501 line too long (80 > 79 characters)
./src/utils/password_prompt.py:73:80: E501 line too long (88 > 79 characters)
./src/utils/password_prompt.py:75:80: E501 line too long (93 > 79 characters)
./src/utils/password_prompt.py:76:80: E501 line too long (96 > 79 characters)
./src/utils/password_prompt.py:80:80: E501 line too long (96 > 79 characters)
./src/utils/password_prompt.py:81:80: E501 line too long (98 > 79 characters)
./src/utils/password_prompt.py:87:80: E501 line too long (99 > 79 characters)
./src/utils/password_prompt.py:106:80: E501 line too long (88 > 79 characters)
./src/utils/password_prompt.py:116:80: E501 line too long (99 > 79 characters)
./src/utils/password_prompt.py:121:80: E501 line too long (93 > 79 characters)
./src/utils/password_prompt.py:129:80: E501 line too long (86 > 79 characters)
./src/utils/password_prompt.py:154:80: E501 line too long (85 > 79 characters)
./src/utils/password_prompt.py:159:80: E501 line too long (81 > 79 characters)
./src/utils/password_prompt.py:168:80: E501 line too long (80 > 79 characters)
./src/utils/password_prompt.py:169:80: E501 line too long (83 > 79 characters)
./src/utils/password_prompt.py:170:80: E501 line too long (80 > 79 characters)
./src/utils/password_prompt.py:192:80: E501 line too long (88 > 79 characters)
./src/utils/password_prompt.py:223:80: E501 line too long (96 > 79 characters)
./src/utils/password_prompt.py:226:80: E501 line too long (89 > 79 characters)
./src/utils/password_prompt.py:261:80: E501 line too long (90 > 79 characters)
./src/utils/password_prompt.py:263:80: E501 line too long (101 > 79 characters)
./src/utils/seed_prompt.py:109:80: E501 line too long (84 > 79 characters)
./src/utils/seed_prompt.py:121:80: E501 line too long (82 > 79 characters)
./src/utils/seed_prompt.py:177:80: E501 line too long (80 > 79 characters)
./src/utils/seed_prompt.py:180:80: E501 line too long (87 > 79 characters)
./src/utils/seed_prompt.py:189:80: E501 line too long (88 > 79 characters)
./src/utils/seed_prompt.py:192:80: E501 line too long (85 > 79 characters)
./src/utils/seed_prompt.py:200:80: E501 line too long (81 > 79 characters)
./src/utils/terminal_utils.py:23:80: E501 line too long (80 > 79 characters)
./src/utils/terminal_utils.py:41:80: E501 line too long (83 > 79 characters)
./src/utils/terminal_utils.py:45:80: E501 line too long (123 > 79 characters)
./src/utils/terminal_utils.py:80:80: E501 line too long (81 > 79 characters)
./src/utils/terminal_utils.py:85:80: E501 line too long (123 > 79 characters)
./tests/perf/test_bip85_cache.py:12:80: E501 line too long (88 > 79 characters)
./tests/perf/test_bip85_cache.py:41:5: F841 local variable 'uncached_time' is assigned to but never used
./tests/perf/test_bip85_cache.py:48:5: F841 local variable 'cached_time' is assigned to but never used
./torch/node_modules/torch-lock/find_dead_code.py:3:1: F401 'sys' imported but unused
./torch/node_modules/torch-lock/find_dead_code.py:5:1: E302 expected 2 blank lines, found 1
./torch/node_modules/torch-lock/find_dead_code.py:8:80: E501 line too long (93 > 79 characters)
./torch/node_modules/torch-lock/find_dead_code.py:15:1: E302 expected 2 blank lines, found 1
./torch/node_modules/torch-lock/find_dead_code.py:41:14: E111 indentation is not a multiple of 4
./torch/node_modules/torch-lock/find_dead_code.py:41:14: E117 over-indented
./torch/node_modules/torch-lock/find_dead_code.py:44:13: E122 continuation line missing indentation or outdented
./torch/node_modules/torch-lock/find_dead_code.py:62:17: E261 at least two spaces before inline comment
./torch/node_modules/torch-lock/find_dead_code.py:64:1: E302 expected 2 blank lines, found 1
./torch/node_modules/torch-lock/find_dead_code.py:68:80: E501 line too long (81 > 79 characters)
./torch/node_modules/torch-lock/find_dead_code.py:72:25: E261 at least two spaces before inline comment
./torch/node_modules/torch-lock/find_dead_code.py:73:31: E261 at least two spaces before inline comment
./torch/node_modules/torch-lock/find_dead_code.py:101:1: E305 expected 2 blank lines after class or function definition, found 1
```

### pytest Output
```
============================= test session starts ==============================
platform linux -- Python 3.12.12, pytest-8.4.1, pluggy-1.6.0
rootdir: /app
configfile: pytest.ini
testpaths: src/tests, tests
plugins: anyio-4.9.0, hypothesis-6.136.7, cov-6.2.1, xdist-3.8.0
created: 4/4 workers
4 workers [661 items]

scheduling tests via LoadScheduling

src/tests/test_bip85_vectors.py::test_bip85_mnemonic_12
src/tests/test_api_new_endpoints.py::test_vault_lock_endpoint[asyncio]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-totp Email --secret JBSW...]
src/tests/test_add_new_fingerprint_words.py::test_add_new_fingerprint_word_entry_exits
[gw0] [  0%] PASSED src/tests/test_add_new_fingerprint_words.py::test_add_new_fingerprint_word_entry_exits
src/tests/test_add_tags_from_retrieve.py::test_add_tags_from_retrieve
[gw2] [  0%] PASSED src/tests/test_bip85_vectors.py::test_bip85_mnemonic_12
src/tests/test_bip85_vectors.py::test_bip85_mnemonic_24
[gw2] [  0%] PASSED src/tests/test_bip85_vectors.py::test_bip85_mnemonic_24
src/tests/test_bip85_vectors.py::test_bip85_symmetric_key
[gw2] [  0%] PASSED src/tests/test_bip85_vectors.py::test_bip85_symmetric_key
src/tests/test_bip85_vectors.py::test_derive_totp_secret
[gw2] [  0%] PASSED src/tests/test_bip85_vectors.py::test_derive_totp_secret
src/tests/test_bip85_vectors.py::test_derive_ssh_key
[gw2] [  0%] PASSED src/tests/test_bip85_vectors.py::test_derive_ssh_key
src/tests/test_bip85_vectors.py::test_derive_seed_phrase
[gw3] [  1%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-totp Email --secret JBSW...]
[gw2] [  1%] PASSED src/tests/test_bip85_vectors.py::test_derive_seed_phrase
src/tests/test_bip85_vectors.py::test_invalid_params
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry archive 1]
[gw2] [  1%] PASSED src/tests/test_bip85_vectors.py::test_invalid_params
src/tests/test_checksum_utils.py::test_json_checksum
[gw2] [  1%] PASSED src/tests/test_checksum_utils.py::test_json_checksum
src/tests/test_checksum_utils.py::test_calculate_checksum
[gw2] [  1%] PASSED src/tests/test_checksum_utils.py::test_calculate_checksum
src/tests/test_checksum_utils.py::test_calculate_checksum_missing
[gw2] [  1%] PASSED src/tests/test_checksum_utils.py::test_calculate_checksum_missing
src/tests/test_checksum_utils.py::test_verify_and_update
[gw2] [  1%] PASSED src/tests/test_checksum_utils.py::test_verify_and_update
src/tests/test_checksum_utils.py::test_initialize_checksum
[gw2] [  2%] PASSED src/tests/test_checksum_utils.py::test_initialize_checksum
src/tests/test_cli_clipboard_flag.py::test_entry_get_handles_missing_clipboard
[gw3] [  2%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry archive 1]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry export-totp --file totp.json]
[gw2] [  2%] PASSED src/tests/test_cli_clipboard_flag.py::test_entry_get_handles_missing_clipboard
src/tests/test_cli_clipboard_flag.py::test_entry_get_no_clipboard_flag
[gw3] [  2%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry export-totp --file totp.json]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry get "GitHub"]
[gw2] [  2%] PASSED src/tests/test_cli_clipboard_flag.py::test_entry_get_no_clipboard_flag
src/tests/test_cli_config_set_extra.py::test_config_set_variants[secret_mode_enabled-true-set_secret_mode_enabled-True]
[gw3] [  2%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry get "GitHub"]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry list]
[gw0] [  3%] PASSED src/tests/test_add_tags_from_retrieve.py::test_add_tags_from_retrieve
src/tests/test_additional_backup.py::test_entry_manager_additional_backup
[gw2] [  3%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[secret_mode_enabled-true-set_secret_mode_enabled-True]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[clipboard_clear_delay-10-set_clipboard_clear_delay-10]
[gw3] [  3%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry list]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry list --sort label]
[gw2] [  3%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[clipboard_clear_delay-10-set_clipboard_clear_delay-10]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[additional_backup_path--set_additional_backup_path-None]
[gw3] [  3%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry list --sort label]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry modify 1 --key new --value updated]
[gw2] [  3%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[additional_backup_path--set_additional_backup_path-None]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[backup_interval-5-set_backup_interval-5.0]
[gw3] [  3%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry modify 1 --key new --value updated]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry search "GitHub"]
[gw2] [  4%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[backup_interval-5-set_backup_interval-5.0]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[kdf_iterations-123-set_kdf_iterations-123]
[gw3] [  4%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry search "GitHub"]
[gw0] [  4%] PASSED src/tests/test_additional_backup.py::test_entry_manager_additional_backup
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry totp-codes]
src/tests/test_api.py::test_token_hashed[asyncio]
[gw2] [  4%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[kdf_iterations-123-set_kdf_iterations-123]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[kdf_mode-argon2-set_kdf_mode-argon2]
[gw2] [  4%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[kdf_mode-argon2-set_kdf_mode-argon2]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[quick_unlock-true-set_quick_unlock-True]
[gw2] [  4%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[quick_unlock-true-set_quick_unlock-True]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[nostr_max_retries-3-set_nostr_max_retries-3]
[gw2] [  4%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[nostr_max_retries-3-set_nostr_max_retries-3]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[nostr_retry_delay-1.5-set_nostr_retry_delay-1.5]
[gw3] [  5%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry totp-codes]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry unarchive 1]
[gw2] [  5%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[nostr_retry_delay-1.5-set_nostr_retry_delay-1.5]
src/tests/test_cli_config_set_extra.py::test_config_set_variants[relays-wss://a.com, wss://b.com-set_relays-expected9]
[gw3] [  5%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry unarchive 1]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[fingerprint add]
[gw2] [  5%] PASSED src/tests/test_cli_config_set_extra.py::test_config_set_variants[relays-wss://a.com, wss://b.com-set_relays-expected9]
src/tests/test_cli_core_services.py::test_cli_vault_unlock
[gw3] [  5%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[fingerprint add]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[fingerprint list]
[gw2] [  5%] PASSED src/tests/test_cli_core_services.py::test_cli_vault_unlock
src/tests/test_cli_core_services.py::test_cli_entry_add_search_sync
[gw3] [  6%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[fingerprint list]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[nostr get-pubkey]
[gw3] [  6%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[nostr get-pubkey]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[nostr sync]
[gw3] [  6%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[nostr sync]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util generate-password]
[gw2] [  6%] PASSED src/tests/test_cli_core_services.py::test_cli_entry_add_search_sync
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[api start]
[gw3] [  6%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util generate-password]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util generate-password --length 24 --special-mode safe --exclude-ambiguous]
[gw2] [  6%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[api start]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[api start --host 0.0.0.0 --port 8000]
[gw3] [  6%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util generate-password --length 24 --special-mode safe --exclude-ambiguous]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util update-checksum]
[gw2] [  7%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[api start --host 0.0.0.0 --port 8000]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config get kdf_iterations]
[gw3] [  7%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util update-checksum]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util verify-checksum]
[gw2] [  7%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config get kdf_iterations]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config set backup_interval 3600]
[gw3] [  7%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[util verify-checksum]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault change-password]
[gw2] [  7%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config set backup_interval 3600]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config set kdf_iterations 200000]
[gw3] [  7%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault change-password]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault lock]
[gw2] [  8%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config set kdf_iterations 200000]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config toggle-offline]
[gw3] [  8%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault lock]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault reveal-parent-seed]
[gw2] [  8%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config toggle-offline]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config toggle-secret-mode]
[gw3] [  8%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault reveal-parent-seed]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault reveal-parent-seed --file backup.enc]
[gw2] [  8%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[config toggle-secret-mode]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry --help]
[gw3] [  8%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault reveal-parent-seed --file backup.enc]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault stats]
[gw2] [  8%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry --help]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add Example --length 16 --no-special --exclude-ambiguous]
[gw3] [  9%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[vault stats]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-add_entry-cli_args0-expected_args0-expected_kwargs0-1]
[gw1] [  9%] PASSED src/tests/test_api_new_endpoints.py::test_vault_lock_endpoint[asyncio]
src/tests/test_api_new_endpoints.py::test_secret_mode_endpoint[asyncio]
[gw2] [  9%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add Example --length 16 --no-special --exclude-ambiguous]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-key-value "API Token" --key api --value abc123]
[gw3] [  9%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-add_entry-cli_args0-expected_args0-expected_kwargs0-1]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-totp-add_totp-cli_args1-expected_args1-expected_kwargs1-otpauth://uri]
[gw2] [  9%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-key-value "API Token" --key api --value abc123]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-managed-account Trading]
[gw3] [  9%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-totp-add_totp-cli_args1-expected_args1-expected_kwargs1-otpauth://uri]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-ssh-add_ssh_key-cli_args2-expected_args2-expected_kwargs2-3]
[gw2] [  9%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-managed-account Trading]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-nostr Chat]
[gw3] [ 10%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-ssh-add_ssh_key-cli_args2-expected_args2-expected_kwargs2-3]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-pgp-add_pgp_key-cli_args3-expected_args3-expected_kwargs3-4]
[gw2] [ 10%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-nostr Chat]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-pgp Personal --user-id me@example.com]
[gw3] [ 10%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-pgp-add_pgp_key-cli_args3-expected_args3-expected_kwargs3-4]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-nostr-add_nostr_key-cli_args4-expected_args4-expected_kwargs4-5]
[gw2] [ 10%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-pgp Personal --user-id me@example.com]
[gw0] [ 10%] PASSED src/tests/test_api.py::test_token_hashed[asyncio]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-seed Backup --words 24]
src/tests/test_api.py::test_cors_and_auth[asyncio]
[gw3] [ 10%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-nostr-add_nostr_key-cli_args4-expected_args4-expected_kwargs4-5]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-seed-add_seed-cli_args5-expected_args5-expected_kwargs5-6]
[gw2] [ 11%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-seed Backup --words 24]
src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-ssh Server --index 0]
[gw3] [ 11%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-seed-add_seed-cli_args5-expected_args5-expected_kwargs5-6]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-key-value-add_key_value-cli_args6-expected_args6-expected_kwargs6-7]
[gw2] [ 11%] PASSED src/tests/test_cli_doc_examples.py::test_doc_cli_examples[entry add-ssh Server --index 0]
src/tests/test_cli_subcommands.py::test_get_command
[gw2] [ 11%] PASSED src/tests/test_cli_subcommands.py::test_get_command
src/tests/test_cli_subcommands.py::test_totp_command
[gw2] [ 11%] PASSED src/tests/test_cli_subcommands.py::test_totp_command
src/tests/test_cli_subcommands.py::test_search_command_no_results
[gw3] [ 11%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-key-value-add_key_value-cli_args6-expected_args6-expected_kwargs6-7]
src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-managed-account-add_managed_account-cli_args7-expected_args7-expected_kwargs7-8]
[gw2] [ 11%] PASSED src/tests/test_cli_subcommands.py::test_search_command_no_results
src/tests/test_cli_subcommands.py::test_get_command_multiple_matches
[gw2] [ 12%] PASSED src/tests/test_cli_subcommands.py::test_get_command_multiple_matches
src/tests/test_cli_subcommands.py::test_get_command_wrong_type
[gw2] [ 12%] PASSED src/tests/test_cli_subcommands.py::test_get_command_wrong_type
src/tests/test_cli_subcommands.py::test_totp_command_multiple_matches
[gw2] [ 12%] PASSED src/tests/test_cli_subcommands.py::test_totp_command_multiple_matches
src/tests/test_cli_subcommands.py::test_totp_command_wrong_type
[gw2] [ 12%] PASSED src/tests/test_cli_subcommands.py::test_totp_command_wrong_type
src/tests/test_cli_subcommands.py::test_main_fingerprint_option
[gw2] [ 12%] PASSED src/tests/test_cli_subcommands.py::test_main_fingerprint_option
src/tests/test_cli_toggle_offline_mode.py::test_toggle_offline_updates
[gw3] [ 12%] PASSED src/tests/test_cli_entry_add_commands.py::test_entry_add_commands[add-managed-account-add_managed_account-cli_args7-expected_args7-expected_kwargs7-8]
src/tests/test_cli_export_import.py::test_cli_export_creates_file
[gw2] [ 13%] PASSED src/tests/test_cli_toggle_offline_mode.py::test_toggle_offline_updates
src/tests/test_cli_toggle_offline_mode.py::test_toggle_offline_keep
[gw2] [ 13%] PASSED src/tests/test_cli_toggle_offline_mode.py::test_toggle_offline_keep
src/tests/test_cli_toggle_secret_mode.py::test_toggle_secret_mode_updates
[gw2] [ 13%] PASSED src/tests/test_cli_toggle_secret_mode.py::test_toggle_secret_mode_updates
src/tests/test_cli_toggle_secret_mode.py::test_toggle_secret_mode_keep
[gw3] [ 13%] PASSED src/tests/test_cli_export_import.py::test_cli_export_creates_file
src/tests/test_cli_export_import.py::test_cli_import_round_trip
[gw2] [ 13%] PASSED src/tests/test_cli_toggle_secret_mode.py::test_toggle_secret_mode_keep
src/tests/test_cli_vault_stats.py::test_vault_stats_command
[gw2] [ 13%] PASSED src/tests/test_cli_vault_stats.py::test_vault_stats_command
src/tests/test_clipboard_utils.py::test_copy_to_clipboard_clears
[gw2] [ 13%] PASSED src/tests/test_clipboard_utils.py::test_copy_to_clipboard_clears
src/tests/test_clipboard_utils.py::test_copy_to_clipboard_does_not_clear_if_changed
[gw2] [ 14%] PASSED src/tests/test_clipboard_utils.py::test_copy_to_clipboard_does_not_clear_if_changed
src/tests/test_clipboard_utils.py::test_copy_to_clipboard_missing_dependency
[gw2] [ 14%] PASSED src/tests/test_clipboard_utils.py::test_copy_to_clipboard_missing_dependency
src/tests/test_concurrency_stress.py::test_concurrency_stress[0-5]
[gw3] [ 14%] PASSED src/tests/test_cli_export_import.py::test_cli_import_round_trip
src/tests/test_cli_export_import.py::test_cli_export_import_unencrypted
[gw3] [ 14%] PASSED src/tests/test_cli_export_import.py::test_cli_export_import_unencrypted
src/tests/test_cli_integration.py::test_cli_integration
[gw2] [ 14%] PASSED src/tests/test_concurrency_stress.py::test_concurrency_stress[0-5]
src/tests/test_concurrency_stress.py::test_concurrency_stress[0-20]
[gw2] [ 14%] SKIPPED src/tests/test_concurrency_stress.py::test_concurrency_stress[0-20]
src/tests/test_concurrency_stress.py::test_concurrency_stress[1-5]
[gw1] [ 14%] PASSED src/tests/test_api_new_endpoints.py::test_secret_mode_endpoint[asyncio]
src/tests/test_api_new_endpoints.py::test_vault_export_endpoint[asyncio]
[gw2] [ 15%] PASSED src/tests/test_concurrency_stress.py::test_concurrency_stress[1-5]
src/tests/test_concurrency_stress.py::test_concurrency_stress[1-20]
[gw2] [ 15%] SKIPPED src/tests/test_concurrency_stress.py::test_concurrency_stress[1-20]
src/tests/test_concurrency_stress.py::test_concurrency_stress[2-5]
[gw0] [ 15%] PASSED src/tests/test_api.py::test_cors_and_auth[asyncio]
src/tests/test_api.py::test_invalid_token[asyncio]
[gw2] [ 15%] PASSED src/tests/test_concurrency_stress.py::test_concurrency_stress[2-5]
src/tests/test_concurrency_stress.py::test_concurrency_stress[2-20]
[gw2] [ 15%] SKIPPED src/tests/test_concurrency_stress.py::test_concurrency_stress[2-20]
src/tests/test_config_manager.py::test_config_defaults_and_round_trip
[gw0] [ 15%] PASSED src/tests/test_api.py::test_invalid_token[asyncio]
src/tests/test_api.py::test_get_entry_by_id[asyncio]
[gw2] [ 16%] PASSED src/tests/test_config_manager.py::test_config_defaults_and_round_trip
src/tests/test_config_manager.py::test_pin_verification_and_change
[gw1] [ 16%] PASSED src/tests/test_api_new_endpoints.py::test_vault_export_endpoint[asyncio]
src/tests/test_api_new_endpoints.py::test_backup_parent_seed_endpoint[asyncio]
[gw3] [ 16%] PASSED src/tests/test_cli_integration.py::test_cli_integration
src/tests/test_cli_invalid_input.py::test_empty_and_non_numeric_choice
[gw3] [ 16%] PASSED src/tests/test_cli_invalid_input.py::test_empty_and_non_numeric_choice
src/tests/test_cli_invalid_input.py::test_out_of_range_menu
[gw3] [ 16%] PASSED src/tests/test_cli_invalid_input.py::test_out_of_range_menu
src/tests/test_cli_invalid_input.py::test_invalid_add_entry_submenu
[gw3] [ 16%] PASSED src/tests/test_cli_invalid_input.py::test_invalid_add_entry_submenu
src/tests/test_cli_invalid_input.py::test_inactivity_timeout_loop
[gw3] [ 16%] PASSED src/tests/test_cli_invalid_input.py::test_inactivity_timeout_loop
src/tests/test_cli_relays.py::test_cli_relay_crud
[gw3] [ 17%] PASSED src/tests/test_cli_relays.py::test_cli_relay_crud
src/tests/test_cli_subcommands.py::test_search_command
[gw3] [ 17%] PASSED src/tests/test_cli_subcommands.py::test_search_command
src/tests/test_config_manager.py::test_backup_interval_round_trip
[gw3] [ 17%] PASSED src/tests/test_config_manager.py::test_backup_interval_round_trip
src/tests/test_config_manager.py::test_quick_unlock_round_trip
[gw0] [ 17%] PASSED src/tests/test_api.py::test_get_entry_by_id[asyncio]
src/tests/test_api.py::test_get_config_value[asyncio]
[gw3] [ 17%] PASSED src/tests/test_config_manager.py::test_quick_unlock_round_trip
src/tests/test_config_manager.py::test_nostr_retry_settings_round_trip
[gw3] [ 17%] PASSED src/tests/test_config_manager.py::test_nostr_retry_settings_round_trip
src/tests/test_config_manager.py::test_special_char_settings_round_trip
[gw3] [ 18%] PASSED src/tests/test_config_manager.py::test_special_char_settings_round_trip
src/tests/test_config_manager.py::test_password_policy_extended_fields
[gw3] [ 18%] PASSED src/tests/test_config_manager.py::test_password_policy_extended_fields
src/tests/test_core_api_services.py::TestVaultService::test_export_vault
[gw3] [ 18%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_export_vault
src/tests/test_core_api_services.py::TestVaultService::test_import_vault
[gw3] [ 18%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_import_vault
src/tests/test_core_api_services.py::TestVaultService::test_export_profile
[gw3] [ 18%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_export_profile
src/tests/test_core_api_services.py::TestVaultService::test_import_profile
[gw3] [ 18%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_import_profile
src/tests/test_core_api_services.py::TestVaultService::test_change_password
[gw3] [ 18%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_change_password
src/tests/test_core_api_services.py::TestVaultService::test_unlock
[gw3] [ 19%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_unlock
src/tests/test_core_api_services.py::TestVaultService::test_lock
[gw3] [ 19%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_lock
src/tests/test_core_api_services.py::TestVaultService::test_backup_parent_seed
[gw3] [ 19%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_backup_parent_seed
src/tests/test_core_api_services.py::TestVaultService::test_stats
[gw3] [ 19%] PASSED src/tests/test_core_api_services.py::TestVaultService::test_stats
src/tests/test_core_api_services.py::TestProfileService::test_list_profiles
[gw3] [ 19%] PASSED src/tests/test_core_api_services.py::TestProfileService::test_list_profiles
src/tests/test_core_api_services.py::TestProfileService::test_add_profile
[gw3] [ 19%] PASSED src/tests/test_core_api_services.py::TestProfileService::test_add_profile
src/tests/test_core_api_services.py::TestProfileService::test_remove_profile
[gw3] [ 19%] PASSED src/tests/test_core_api_services.py::TestProfileService::test_remove_profile
src/tests/test_core_api_services.py::TestProfileService::test_switch_profile
[gw3] [ 20%] PASSED src/tests/test_core_api_services.py::TestProfileService::test_switch_profile
src/tests/test_core_api_services.py::TestSyncService::test_sync
[gw3] [ 20%] PASSED src/tests/test_core_api_services.py::TestSyncService::test_sync
src/tests/test_core_api_services.py::TestSyncService::test_sync_none
[gw3] [ 20%] PASSED src/tests/test_core_api_services.py::TestSyncService::test_sync_none
src/tests/test_core_api_services.py::TestSyncService::test_start_background_sync
[gw3] [ 20%] PASSED src/tests/test_core_api_services.py::TestSyncService::test_start_background_sync
src/tests/test_core_api_services.py::TestSyncService::test_start_background_vault_sync
[gw3] [ 20%] PASSED src/tests/test_core_api_services.py::TestSyncService::test_start_background_vault_sync
src/tests/test_core_api_services.py::TestEntryService::test_list_entries
[gw3] [ 20%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_list_entries
src/tests/test_core_api_services.py::TestEntryService::test_search_entries
[gw3] [ 21%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_search_entries
src/tests/test_core_api_services.py::TestEntryService::test_retrieve_entry
[gw3] [ 21%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_retrieve_entry
src/tests/test_core_api_services.py::TestEntryService::test_generate_password_default
[gw3] [ 21%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_generate_password_default
src/tests/test_core_api_services.py::TestEntryService::test_generate_password_custom
[gw3] [ 21%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_generate_password_custom
src/tests/test_core_api_services.py::TestEntryService::test_get_totp_code
[gw3] [ 21%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_get_totp_code
src/tests/test_core_api_services.py::TestEntryService::test_add_entry
[gw3] [ 21%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_entry
src/tests/test_core_api_services.py::TestEntryService::test_add_totp
[gw3] [ 21%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_totp
src/tests/test_core_services.py::test_vault_service_unlock
[gw3] [ 22%] PASSED src/tests/test_core_services.py::test_vault_service_unlock
src/tests/test_core_services.py::test_entry_service_add_entry_and_search
[gw3] [ 22%] PASSED src/tests/test_core_services.py::test_entry_service_add_entry_and_search
src/tests/test_core_services.py::test_sync_service_sync
[gw3] [ 22%] PASSED src/tests/test_core_services.py::test_sync_service_sync
src/tests/test_custom_fields_display.py::test_retrieve_entry_shows_custom_fields
[gw1] [ 22%] PASSED src/tests/test_api_new_endpoints.py::test_backup_parent_seed_endpoint[asyncio]
src/tests/test_api_new_endpoints.py::test_backup_parent_seed_path_traversal_blocked[asyncio]
[gw3] [ 22%] PASSED src/tests/test_custom_fields_display.py::test_retrieve_entry_shows_custom_fields
src/tests/test_decrypt_messages.py::test_wrong_password_message
[gw3] [ 22%] PASSED src/tests/test_decrypt_messages.py::test_wrong_password_message
src/tests/test_decrypt_messages.py::test_legacy_file_requires_migration_message
[gw3] [ 22%] PASSED src/tests/test_decrypt_messages.py::test_legacy_file_requires_migration_message
src/tests/test_decrypt_messages.py::test_corrupted_data_message
[gw3] [ 23%] PASSED src/tests/test_decrypt_messages.py::test_corrupted_data_message
src/tests/test_default_encryption_mode.py::test_default_encryption_mode
[gw3] [ 23%] PASSED src/tests/test_default_encryption_mode.py::test_default_encryption_mode
src/tests/test_delta_merge.py::test_merge_modified_ts
[gw0] [ 23%] PASSED src/tests/test_api.py::test_get_config_value[asyncio]
src/tests/test_api.py::test_list_fingerprint[asyncio]
[gw3] [ 23%] PASSED src/tests/test_delta_merge.py::test_merge_modified_ts
src/tests/test_duplicate_seed_profile_creation.py::test_duplicate_seed_profile_creation
[gw3] [ 23%] PASSED src/tests/test_duplicate_seed_profile_creation.py::test_duplicate_seed_profile_creation
src/tests/test_edit_tags_from_retrieve.py::test_edit_tags_from_retrieve
[gw3] [ 23%] PASSED src/tests/test_edit_tags_from_retrieve.py::test_edit_tags_from_retrieve
src/tests/test_encryption_checksum.py::test_encryption_checksum_workflow
[gw3] [ 24%] PASSED src/tests/test_encryption_checksum.py::test_encryption_checksum_workflow
src/tests/test_encryption_checksum.py::test_update_checksum_removes_legacy
[gw3] [ 24%] PASSED src/tests/test_encryption_checksum.py::test_update_checksum_removes_legacy
src/tests/test_encryption_files.py::test_json_save_and_load_round_trip
[gw3] [ 24%] PASSED src/tests/test_encryption_files.py::test_json_save_and_load_round_trip
src/tests/test_encryption_files.py::test_encrypt_and_decrypt_file_binary_round_trip
[gw3] [ 24%] PASSED src/tests/test_encryption_files.py::test_encrypt_and_decrypt_file_binary_round_trip
src/tests/test_encryption_files.py::test_encrypt_file_rejects_traversal
[gw3] [ 24%] PASSED src/tests/test_encryption_files.py::test_encrypt_file_rejects_traversal
src/tests/test_encryption_fuzz.py::test_encrypt_decrypt_roundtrip
[gw1] [ 24%] PASSED src/tests/test_api_new_endpoints.py::test_backup_parent_seed_path_traversal_blocked[asyncio]
src/tests/test_api_new_endpoints.py::test_relay_management_endpoints[asyncio]
[gw0] [ 24%] PASSED src/tests/test_api.py::test_list_fingerprint[asyncio]
src/tests/test_api.py::test_get_nostr_pubkey[asyncio]
[gw2] [ 25%] PASSED src/tests/test_config_manager.py::test_pin_verification_and_change
src/tests/test_config_manager.py::test_config_file_encrypted_after_save
[gw3] [ 25%] PASSED src/tests/test_encryption_fuzz.py::test_encrypt_decrypt_roundtrip
src/tests/test_encryption_fuzz.py::test_corrupted_ciphertext_fails
[gw2] [ 25%] PASSED src/tests/test_config_manager.py::test_config_file_encrypted_after_save
src/tests/test_config_manager.py::test_set_relays_persists_changes
[gw3] [ 25%] PASSED src/tests/test_encryption_fuzz.py::test_corrupted_ciphertext_fails
src/tests/test_encryption_validate_seed.py::test_validate_seed_valid_mnemonic
[gw3] [ 25%] PASSED src/tests/test_encryption_validate_seed.py::test_validate_seed_valid_mnemonic
src/tests/test_encryption_validate_seed.py::test_validate_seed_invalid_mnemonic
[gw3] [ 25%] PASSED src/tests/test_encryption_validate_seed.py::test_validate_seed_invalid_mnemonic
src/tests/test_entries_empty.py::test_list_entries_empty
[gw2] [ 26%] PASSED src/tests/test_config_manager.py::test_set_relays_persists_changes
src/tests/test_config_manager.py::test_set_relays_requires_at_least_one
[gw3] [ 26%] PASSED src/tests/test_entries_empty.py::test_list_entries_empty
src/tests/test_entry_add.py::test_add_and_retrieve_entry
[gw2] [ 26%] PASSED src/tests/test_config_manager.py::test_set_relays_requires_at_least_one
src/tests/test_config_manager.py::test_inactivity_timeout_round_trip
[gw3] [ 26%] PASSED src/tests/test_entry_add.py::test_add_and_retrieve_entry
src/tests/test_entry_add.py::test_round_trip_entry_types[add_entry-password]
[gw2] [ 26%] PASSED src/tests/test_config_manager.py::test_inactivity_timeout_round_trip
src/tests/test_config_manager.py::test_password_hash_migrates_from_file
[gw3] [ 26%] PASSED src/tests/test_entry_add.py::test_round_trip_entry_types[add_entry-password]
src/tests/test_entry_add.py::test_round_trip_entry_types[add_totp-totp]
[gw0] [ 26%] PASSED src/tests/test_api.py::test_get_nostr_pubkey[asyncio]
src/tests/test_api.py::test_create_modify_archive_entry[asyncio]
[gw3] [ 27%] PASSED src/tests/test_entry_add.py::test_round_trip_entry_types[add_totp-totp]
src/tests/test_entry_add.py::test_round_trip_entry_types[add_ssh_key-ssh]
[gw3] [ 27%] PASSED src/tests/test_entry_add.py::test_round_trip_entry_types[add_ssh_key-ssh]
src/tests/test_entry_add.py::test_round_trip_entry_types[add_seed-seed]
[gw3] [ 27%] PASSED src/tests/test_entry_add.py::test_round_trip_entry_types[add_seed-seed]
src/tests/test_entry_add.py::test_round_trip_entry_types[add_key_value-key_value]
[gw3] [ 27%] PASSED src/tests/test_entry_add.py::test_round_trip_entry_types[add_key_value-key_value]
src/tests/test_entry_add.py::test_round_trip_entry_types[add_managed_account-managed_account]
[gw2] [ 27%] PASSED src/tests/test_config_manager.py::test_password_hash_migrates_from_file
src/tests/test_config_manager.py::test_additional_backup_path_round_trip
[gw3] [ 27%] PASSED src/tests/test_entry_add.py::test_round_trip_entry_types[add_managed_account-managed_account]
src/tests/test_entry_add.py::test_legacy_entry_defaults_to_password
[gw2] [ 27%] PASSED src/tests/test_config_manager.py::test_additional_backup_path_round_trip
src/tests/test_config_manager.py::test_secret_mode_round_trip
[gw3] [ 28%] PASSED src/tests/test_entry_add.py::test_legacy_entry_defaults_to_password
src/tests/test_entry_add.py::test_add_default_archived_false[add_entry-args0]
[gw2] [ 28%] PASSED src/tests/test_config_manager.py::test_secret_mode_round_trip
src/tests/test_config_manager.py::test_kdf_iterations_round_trip
[gw3] [ 28%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_entry-args0]
src/tests/test_entry_add.py::test_add_default_archived_false[add_totp-args1]
[gw2] [ 28%] PASSED src/tests/test_config_manager.py::test_kdf_iterations_round_trip
src/tests/test_core_api_services.py::TestEntryService::test_add_ssh_key
[gw2] [ 28%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_ssh_key
src/tests/test_core_api_services.py::TestEntryService::test_add_pgp_key
[gw2] [ 28%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_pgp_key
src/tests/test_core_api_services.py::TestEntryService::test_add_nostr_key
[gw2] [ 29%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_nostr_key
src/tests/test_core_api_services.py::TestEntryService::test_add_seed
[gw2] [ 29%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_seed
src/tests/test_core_api_services.py::TestEntryService::test_add_key_value
[gw2] [ 29%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_key_value
src/tests/test_core_api_services.py::TestEntryService::test_add_managed_account
[gw2] [ 29%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_add_managed_account
src/tests/test_core_api_services.py::TestEntryService::test_modify_entry
[gw2] [ 29%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_modify_entry
[gw3] [ 29%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_totp-args1]
src/tests/test_entry_add.py::test_add_default_archived_false[add_ssh_key-args2]
src/tests/test_core_api_services.py::TestEntryService::test_archive_entry
[gw2] [ 29%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_archive_entry
src/tests/test_core_api_services.py::TestEntryService::test_restore_entry
[gw2] [ 30%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_restore_entry
src/tests/test_core_api_services.py::TestEntryService::test_export_totp_entries
[gw2] [ 30%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_export_totp_entries
src/tests/test_core_api_services.py::TestEntryService::test_display_totp_codes
[gw2] [ 30%] PASSED src/tests/test_core_api_services.py::TestEntryService::test_display_totp_codes
src/tests/test_core_api_services.py::TestConfigService::test_get
[gw2] [ 30%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_get
src/tests/test_core_api_services.py::TestConfigService::test_set_simple
[gw2] [ 30%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_set_simple
src/tests/test_core_api_services.py::TestConfigService::test_set_bool
[gw2] [ 30%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_set_bool
src/tests/test_core_api_services.py::TestConfigService::test_set_relays
[gw2] [ 31%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_set_relays
src/tests/test_core_api_services.py::TestConfigService::test_set_invalid_key
[gw2] [ 31%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_set_invalid_key
src/tests/test_core_api_services.py::TestConfigService::test_get_secret_mode_enabled
[gw2] [ 31%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_get_secret_mode_enabled
src/tests/test_core_api_services.py::TestConfigService::test_get_clipboard_clear_delay
[gw2] [ 31%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_get_clipboard_clear_delay
src/tests/test_core_api_services.py::TestConfigService::test_set_secret_mode
[gw2] [ 31%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_set_secret_mode
src/tests/test_core_api_services.py::TestConfigService::test_get_offline_mode
[gw2] [ 31%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_get_offline_mode
src/tests/test_core_api_services.py::TestConfigService::test_set_offline_mode
[gw2] [ 31%] PASSED src/tests/test_core_api_services.py::TestConfigService::test_set_offline_mode
src/tests/test_core_api_services.py::TestUtilityService::test_generate_password
[gw3] [ 32%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_ssh_key-args2]
[gw2] [ 32%] PASSED src/tests/test_core_api_services.py::TestUtilityService::test_generate_password
src/tests/test_entry_add.py::test_add_default_archived_false[add_pgp_key-args3]
src/tests/test_core_api_services.py::TestUtilityService::test_verify_checksum
[gw2] [ 32%] PASSED src/tests/test_core_api_services.py::TestUtilityService::test_verify_checksum
src/tests/test_core_api_services.py::TestUtilityService::test_update_checksum
[gw2] [ 32%] PASSED src/tests/test_core_api_services.py::TestUtilityService::test_update_checksum
src/tests/test_core_api_services.py::TestNostrService::test_get_pubkey
[gw1] [ 32%] PASSED src/tests/test_api_new_endpoints.py::test_relay_management_endpoints[asyncio]
[gw2] [ 32%] PASSED src/tests/test_core_api_services.py::TestNostrService::test_get_pubkey
src/tests/test_core_api_services.py::TestNostrService::test_list_relays
src/tests/test_api_new_endpoints.py::test_generate_password_no_special_chars[asyncio]
[gw2] [ 32%] PASSED src/tests/test_core_api_services.py::TestNostrService::test_list_relays
src/tests/test_core_api_services.py::TestNostrService::test_add_relay
[gw2] [ 33%] PASSED src/tests/test_core_api_services.py::TestNostrService::test_add_relay
src/tests/test_core_api_services.py::TestNostrService::test_remove_relay
[gw2] [ 33%] PASSED src/tests/test_core_api_services.py::TestNostrService::test_remove_relay
src/tests/test_get_entry_summaries_archived_view.py::test_get_entry_summaries_excludes_archived_and_view_handler
[gw2] [ 33%] PASSED src/tests/test_get_entry_summaries_archived_view.py::test_get_entry_summaries_excludes_archived_and_view_handler
src/tests/test_get_entry_summaries_updates.py::test_get_entry_summaries_updates_label
[gw3] [ 33%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_pgp_key-args3]
src/tests/test_entry_add.py::test_add_default_archived_false[add_nostr_key-args4]
[gw2] [ 33%] PASSED src/tests/test_get_entry_summaries_updates.py::test_get_entry_summaries_updates_label
src/tests/test_get_entry_summaries_updates.py::test_get_entry_summaries_updates_archive_restore
[gw3] [ 33%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_nostr_key-args4]
src/tests/test_entry_add.py::test_add_default_archived_false[add_seed-args5]
[gw2] [ 34%] PASSED src/tests/test_get_entry_summaries_updates.py::test_get_entry_summaries_updates_archive_restore
src/tests/test_gui_features.py::test_relay_manager_add_remove
[gw2] [ 34%] SKIPPED src/tests/test_gui_features.py::test_relay_manager_add_remove
src/tests/test_gui_features.py::test_status_bar_updates_and_lock
[gw2] [ 34%] SKIPPED src/tests/test_gui_features.py::test_status_bar_updates_and_lock
src/tests/test_gui_features.py::test_totp_viewer_refresh_on_sync
[gw2] [ 34%] SKIPPED src/tests/test_gui_features.py::test_totp_viewer_refresh_on_sync
src/tests/test_gui_headless.py::test_unlock_creates_main_window
[gw3] [ 34%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_seed-args5]
src/tests/test_entry_add.py::test_add_default_archived_false[add_key_value-args6]
[gw2] [ 34%] PASSED src/tests/test_gui_headless.py::test_unlock_creates_main_window
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[password-expect0]
[gw2] [ 34%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[password-expect0]
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[totp-expect1]
[gw2] [ 35%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[totp-expect1]
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[ssh-expect2]
[gw2] [ 35%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[ssh-expect2]
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[seed-expect3]
[gw2] [ 35%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[seed-expect3]
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[pgp-expect4]
[gw3] [ 35%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_key_value-args6]
src/tests/test_entry_add.py::test_add_default_archived_false[add_managed_account-args7]
[gw2] [ 35%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[pgp-expect4]
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[nostr-expect5]
[gw2] [ 35%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[nostr-expect5]
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[key_value-expect6]
[gw2] [ 36%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[key_value-expect6]
src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[managed_account-expect7]
[gw2] [ 36%] PASSED src/tests/test_gui_headless.py::test_entrydialog_add_calls_service[managed_account-expect7]
src/tests/test_gui_headless.py::test_entrydialog_edit_calls_service[password-expected0]
[gw2] [ 36%] PASSED src/tests/test_gui_headless.py::test_entrydialog_edit_calls_service[password-expected0]
src/tests/test_gui_headless.py::test_entrydialog_edit_calls_service[key_value-expected1]
[gw2] [ 36%] PASSED src/tests/test_gui_headless.py::test_entrydialog_edit_calls_service[key_value-expected1]
src/tests/test_gui_headless.py::test_entrydialog_edit_calls_service[totp-expected2]
[gw2] [ 36%] PASSED src/tests/test_gui_headless.py::test_entrydialog_edit_calls_service[totp-expected2]
src/tests/test_gui_sync.py::test_start_vault_sync_schedules_task
[gw2] [ 36%] PASSED src/tests/test_gui_sync.py::test_start_vault_sync_schedules_task
src/tests/test_gui_sync.py::test_status_updates_on_bus_events
[gw3] [ 36%] PASSED src/tests/test_entry_add.py::test_add_default_archived_false[add_managed_account-args7]
[gw2] [ 37%] PASSED src/tests/test_gui_sync.py::test_status_updates_on_bus_events
src/tests/test_handle_switch_fingerprint.py::test_handle_switch_fingerprint_active_profile
[gw2] [ 37%] PASSED src/tests/test_handle_switch_fingerprint.py::test_handle_switch_fingerprint_active_profile
src/tests/test_inactivity_lock.py::test_inactivity_triggers_lock
[gw2] [ 37%] PASSED src/tests/test_inactivity_lock.py::test_inactivity_triggers_lock
src/tests/test_inactivity_lock.py::test_input_timeout_triggers_lock
[gw2] [ 37%] PASSED src/tests/test_inactivity_lock.py::test_input_timeout_triggers_lock
src/tests/test_inactivity_lock.py::test_update_activity_checks_timeout
src/tests/test_entry_management_checksum_path.py::test_update_checksum_writes_to_expected_path
[gw2] [ 37%] PASSED src/tests/test_inactivity_lock.py::test_update_activity_checks_timeout
src/tests/test_index_cache.py::test_index_caching
[gw3] [ 37%] PASSED src/tests/test_entry_management_checksum_path.py::test_update_checksum_writes_to_expected_path
src/tests/test_entry_management_checksum_path.py::test_backup_index_file_creates_backup_in_directory
[gw2] [ 37%] PASSED src/tests/test_index_cache.py::test_index_caching
src/tests/test_index_import_export.py::test_index_export_import_round_trip
[gw1] [ 38%] PASSED src/tests/test_api_new_endpoints.py::test_generate_password_no_special_chars[asyncio]
src/tests/test_api_new_endpoints.py::test_generate_password_allowed_chars[asyncio]
[gw0] [ 38%] PASSED src/tests/test_api.py::test_create_modify_archive_entry[asyncio]
src/tests/test_api.py::test_update_config[asyncio]
[gw3] [ 38%] PASSED src/tests/test_entry_management_checksum_path.py::test_backup_index_file_creates_backup_in_directory
src/tests/test_entry_policy_override.py::test_entry_policy_override_changes_password
[gw2] [ 38%] PASSED src/tests/test_index_import_export.py::test_index_export_import_round_trip
src/tests/test_index_import_export.py::test_get_encrypted_index_missing_file
[gw2] [ 38%] PASSED src/tests/test_index_import_export.py::test_get_encrypted_index_missing_file
src/tests/test_invalid_password_message.py::test_invalid_password_shows_friendly_message_once
[gw3] [ 38%] PASSED src/tests/test_entry_policy_override.py::test_entry_policy_override_changes_password
src/tests/test_export_totp_codes.py::test_handle_export_totp_codes
[gw2] [ 39%] PASSED src/tests/test_invalid_password_message.py::test_invalid_password_shows_friendly_message_once
src/tests/test_kdf_iteration_fallback.py::test_kdf_iteration_fallback
[gw3] [ 39%] PASSED src/tests/test_export_totp_codes.py::test_handle_export_totp_codes
src/tests/test_file_lock.py::test_exclusive_lock_blocks_until_released
[gw0] [ 39%] PASSED src/tests/test_api.py::test_update_config[asyncio]
src/tests/test_api.py::test_update_config_quick_unlock[asyncio]
[gw1] [ 39%] PASSED src/tests/test_api_new_endpoints.py::test_generate_password_allowed_chars[asyncio]
src/tests/test_api_notifications.py::test_notifications_endpoint[asyncio]
[gw2] [ 39%] PASSED src/tests/test_kdf_iteration_fallback.py::test_kdf_iteration_fallback
src/tests/test_kdf_modes.py::test_setup_encryption_manager_kdf_modes
[gw3] [ 39%] PASSED src/tests/test_file_lock.py::test_exclusive_lock_blocks_until_released
src/tests/test_file_locking.py::test_concurrent_shared_and_exclusive_lock
[gw3] [ 39%] PASSED src/tests/test_file_locking.py::test_concurrent_shared_and_exclusive_lock
src/tests/test_fingerprint_encryption.py::test_generate_fingerprint_deterministic
[gw3] [ 40%] PASSED src/tests/test_fingerprint_encryption.py::test_generate_fingerprint_deterministic
src/tests/test_fingerprint_encryption.py::test_encryption_round_trip
[gw3] [ 40%] PASSED src/tests/test_fingerprint_encryption.py::test_encryption_round_trip
src/tests/test_fingerprint_manager_utils.py::test_add_and_remove_fingerprint
[gw3] [ 40%] PASSED src/tests/test_fingerprint_manager_utils.py::test_add_and_remove_fingerprint
src/tests/test_fingerprint_manager_utils.py::test_remove_nonexistent_fingerprint
[gw3] [ 40%] PASSED src/tests/test_fingerprint_manager_utils.py::test_remove_nonexistent_fingerprint
src/tests/test_full_sync_roundtrip.py::test_full_sync_roundtrip
[gw0] [ 40%] PASSED src/tests/test_api.py::test_update_config_quick_unlock[asyncio]
src/tests/test_api.py::test_change_password_route[asyncio]
[gw1] [ 40%] PASSED src/tests/test_api_notifications.py::test_notifications_endpoint[asyncio]
src/tests/test_api_notifications.py::test_notifications_endpoint_clears_queue[asyncio]
[gw2] [ 40%] PASSED src/tests/test_kdf_modes.py::test_setup_encryption_manager_kdf_modes
src/tests/test_kdf_modes.py::test_kdf_param_round_trip
[gw2] [ 41%] PASSED src/tests/test_kdf_modes.py::test_kdf_param_round_trip
src/tests/test_kdf_modes.py::test_vault_kdf_migration
[gw2] [ 41%] PASSED src/tests/test_kdf_modes.py::test_vault_kdf_migration
src/tests/test_kdf_strength_slider.py::test_kdf_strength_slider_persists
[gw3] [ 41%] PASSED src/tests/test_full_sync_roundtrip.py::test_full_sync_roundtrip
src/tests/test_full_sync_roundtrip_new.py::test_full_sync_roundtrip
[gw2] [ 41%] PASSED src/tests/test_kdf_strength_slider.py::test_kdf_strength_slider_persists
src/tests/test_key_derivation.py::test_pbkdf2_fingerprint_affects_key
[gw2] [ 41%] PASSED src/tests/test_key_derivation.py::test_pbkdf2_fingerprint_affects_key
src/tests/test_key_derivation.py::test_derive_key_empty_password_error
[gw2] [ 41%] PASSED src/tests/test_key_derivation.py::test_derive_key_empty_password_error
src/tests/test_key_derivation.py::test_seed_only_key_deterministic
[gw2] [ 42%] PASSED src/tests/test_key_derivation.py::test_seed_only_key_deterministic
src/tests/test_key_derivation.py::test_derive_index_key_seed_only
[gw2] [ 42%] PASSED src/tests/test_key_derivation.py::test_derive_index_key_seed_only
src/tests/test_key_derivation.py::test_argon2_fingerprint_affects_key
[gw2] [ 42%] PASSED src/tests/test_key_derivation.py::test_argon2_fingerprint_affects_key
src/tests/test_key_hierarchy.py::test_kd_distinct_infos
[gw2] [ 42%] PASSED src/tests/test_key_hierarchy.py::test_kd_distinct_infos
src/tests/test_key_hierarchy.py::test_derive_index_key_matches_hierarchy
[gw2] [ 42%] PASSED src/tests/test_key_hierarchy.py::test_derive_index_key_matches_hierarchy
src/tests/test_key_manager_helpers.py::test_key_manager_getters
[gw2] [ 42%] PASSED src/tests/test_key_manager_helpers.py::test_key_manager_getters
src/tests/test_key_validation_failures.py::test_add_totp_invalid_secret
[gw2] [ 42%] PASSED src/tests/test_key_validation_failures.py::test_add_totp_invalid_secret
src/tests/test_key_validation_failures.py::test_add_ssh_key_validation_failure
[gw3] [ 43%] PASSED src/tests/test_full_sync_roundtrip_new.py::test_full_sync_roundtrip
src/tests/test_fuzz_key_derivation.py::test_fuzz_key_round_trip
[gw2] [ 43%] PASSED src/tests/test_key_validation_failures.py::test_add_ssh_key_validation_failure
src/tests/test_key_validation_failures.py::test_add_pgp_key_validation_failure
[gw2] [ 43%] PASSED src/tests/test_key_validation_failures.py::test_add_pgp_key_validation_failure
src/tests/test_key_validation_failures.py::test_add_nostr_key_validation_failure
[gw0] [ 43%] PASSED src/tests/test_api.py::test_change_password_route[asyncio]
src/tests/test_api.py::test_update_config_unknown_key[asyncio]
[gw2] [ 43%] PASSED src/tests/test_key_validation_failures.py::test_add_nostr_key_validation_failure
src/tests/test_list_entries_sort_filter.py::test_sort_by_updated
[gw2] [ 43%] PASSED src/tests/test_list_entries_sort_filter.py::test_sort_by_updated
src/tests/test_list_entries_sort_filter.py::test_filter_by_type
[gw2] [ 44%] PASSED src/tests/test_list_entries_sort_filter.py::test_filter_by_type
src/tests/test_load_global_config.py::test_load_global_config_invalid_toml
[gw2] [ 44%] PASSED src/tests/test_load_global_config.py::test_load_global_config_invalid_toml
src/tests/test_managed_account.py::test_add_managed_account_fields_and_dir
[gw2] [ 44%] PASSED src/tests/test_managed_account.py::test_add_managed_account_fields_and_dir
src/tests/test_managed_account.py::test_load_and_exit_managed_account
[gw1] [ 44%] PASSED src/tests/test_api_notifications.py::test_notifications_endpoint_clears_queue[asyncio]
src/tests/test_api_notifications.py::test_notifications_endpoint_does_not_clear_current[asyncio]
[gw2] [ 44%] PASSED src/tests/test_managed_account.py::test_load_and_exit_managed_account
src/tests/test_managed_account_entry.py::test_add_and_get_managed_account_seed
[gw2] [ 44%] PASSED src/tests/test_managed_account_entry.py::test_add_and_get_managed_account_seed
src/tests/test_managed_account_entry.py::test_load_and_exit_managed_account
[gw0] [ 44%] PASSED src/tests/test_api.py::test_update_config_unknown_key[asyncio]
src/tests/test_api.py::test_shutdown[asyncio]
[gw2] [ 45%] PASSED src/tests/test_managed_account_entry.py::test_load_and_exit_managed_account
src/tests/test_manager_add_password.py::test_handle_add_password
[gw2] [ 45%] PASSED src/tests/test_manager_add_password.py::test_handle_add_password
src/tests/test_manager_add_password.py::test_handle_add_password_secret_mode
[gw2] [ 45%] PASSED src/tests/test_manager_add_password.py::test_handle_add_password_secret_mode
src/tests/test_manager_add_password.py::test_handle_add_password_quick_mode
[gw2] [ 45%] PASSED src/tests/test_manager_add_password.py::test_handle_add_password_quick_mode
src/tests/test_manager_add_totp.py::test_handle_add_totp
[gw1] [ 45%] PASSED src/tests/test_api_notifications.py::test_notifications_endpoint_does_not_clear_current[asyncio]
src/tests/test_api_profile_stats.py::test_profile_stats_endpoint[asyncio]
[gw2] [ 45%] PASSED src/tests/test_manager_add_totp.py::test_handle_add_totp
src/tests/test_manager_checksum_backup.py::test_handle_verify_checksum_success
[gw2] [ 45%] PASSED src/tests/test_manager_checksum_backup.py::test_handle_verify_checksum_success
src/tests/test_manager_checksum_backup.py::test_handle_verify_checksum_failure
[gw2] [ 46%] PASSED src/tests/test_manager_checksum_backup.py::test_handle_verify_checksum_failure
src/tests/test_manager_checksum_backup.py::test_handle_verify_checksum_missing
[gw2] [ 46%] PASSED src/tests/test_manager_checksum_backup.py::test_handle_verify_checksum_missing
src/tests/test_manager_checksum_backup.py::test_backup_and_restore_database
[gw2] [ 46%] PASSED src/tests/test_manager_checksum_backup.py::test_backup_and_restore_database
src/tests/test_manager_current_notification.py::test_notify_sets_current
[gw2] [ 46%] PASSED src/tests/test_manager_current_notification.py::test_notify_sets_current
src/tests/test_manager_current_notification.py::test_get_current_notification_ttl
[gw2] [ 46%] PASSED src/tests/test_manager_current_notification.py::test_get_current_notification_ttl
src/tests/test_manager_display_totp_codes.py::test_handle_display_totp_codes
[gw2] [ 46%] PASSED src/tests/test_manager_display_totp_codes.py::test_handle_display_totp_codes
src/tests/test_manager_display_totp_codes.py::test_display_totp_codes_excludes_archived
[gw2] [ 47%] PASSED src/tests/test_manager_display_totp_codes.py::test_display_totp_codes_excludes_archived
src/tests/test_manager_edit_totp.py::test_edit_totp_period_from_retrieve
[gw0] [ 47%] PASSED src/tests/test_api.py::test_shutdown[asyncio]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/entry/1]
[gw2] [ 47%] PASSED src/tests/test_manager_edit_totp.py::test_edit_totp_period_from_retrieve
src/tests/test_manager_import_database.py::test_import_non_backup_file
[gw2] [ 47%] PASSED src/tests/test_manager_import_database.py::test_import_non_backup_file
src/tests/test_manager_import_database.py::test_import_missing_file
[gw2] [ 47%] PASSED src/tests/test_manager_import_database.py::test_import_missing_file
src/tests/test_manager_list_entries.py::test_handle_list_entries
[gw2] [ 47%] PASSED src/tests/test_manager_list_entries.py::test_handle_list_entries
src/tests/test_manager_list_entries.py::test_list_entries_show_details
[gw2] [ 47%] PASSED src/tests/test_manager_list_entries.py::test_list_entries_show_details
src/tests/test_manager_list_entries.py::test_show_entry_details_by_index
[gw1] [ 48%] PASSED src/tests/test_api_profile_stats.py::test_profile_stats_endpoint[asyncio]
src/tests/test_api_rate_limit.py::test_rate_limit_exceeded[asyncio]
[gw2] [ 48%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_by_index
src/tests/test_manager_list_entries.py::test_show_seed_entry_details
[gw2] [ 48%] PASSED src/tests/test_manager_list_entries.py::test_show_seed_entry_details
src/tests/test_manager_list_entries.py::test_show_ssh_entry_details
[gw2] [ 48%] PASSED src/tests/test_manager_list_entries.py::test_show_ssh_entry_details
src/tests/test_manager_list_entries.py::test_show_pgp_entry_details
[gw0] [ 48%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/entry/1]
[gw2] [ 48%] PASSED src/tests/test_manager_list_entries.py::test_show_pgp_entry_details
src/tests/test_manager_list_entries.py::test_show_nostr_entry_details
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/config/k]
[gw2] [ 49%] PASSED src/tests/test_manager_list_entries.py::test_show_nostr_entry_details
src/tests/test_manager_list_entries.py::test_show_managed_account_entry_details
[gw2] [ 49%] PASSED src/tests/test_manager_list_entries.py::test_show_managed_account_entry_details
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[password]
[gw2] [ 49%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[password]
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[seed]
[gw2] [ 49%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[seed]
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[ssh]
[gw2] [ 49%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[ssh]
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[pgp]
[gw2] [ 49%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[pgp]
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[nostr]
[gw0] [ 49%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/config/k]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/fingerprint]
[gw1] [ 50%] PASSED src/tests/test_api_rate_limit.py::test_rate_limit_exceeded[asyncio]
src/tests/test_api_reload_relays.py::test_reload_relays_logs_errors
[gw1] [ 50%] PASSED src/tests/test_api_reload_relays.py::test_reload_relays_logs_errors
src/tests/test_archive_from_retrieve.py::test_archive_entry_from_retrieve
[gw2] [ 50%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[nostr]
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[totp]
[gw1] [ 50%] PASSED src/tests/test_archive_from_retrieve.py::test_archive_entry_from_retrieve
src/tests/test_archive_from_retrieve.py::test_restore_entry_from_retrieve
[gw2] [ 50%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[totp]
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[key_value]
[gw1] [ 50%] PASSED src/tests/test_archive_from_retrieve.py::test_restore_entry_from_retrieve
src/tests/test_archive_nonpassword.py::test_archive_nonpassword_list_search
[gw2] [ 50%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[key_value]
src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[managed_account]
[gw1] [ 51%] PASSED src/tests/test_archive_nonpassword.py::test_archive_nonpassword_list_search
src/tests/test_archive_restore.py::test_archive_restore_affects_listing_and_search
[gw2] [ 51%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_sensitive[managed_account]
src/tests/test_manager_list_entries.py::test_show_entry_details_with_enum_type[password]
[gw1] [ 51%] PASSED src/tests/test_archive_restore.py::test_archive_restore_affects_listing_and_search
src/tests/test_archive_restore.py::test_view_archived_entries_cli
[gw2] [ 51%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_with_enum_type[password]
src/tests/test_manager_list_entries.py::test_show_entry_details_with_enum_type[totp]
[gw1] [ 51%] PASSED src/tests/test_archive_restore.py::test_view_archived_entries_cli
src/tests/test_archive_restore.py::test_view_archived_entries_view_only
[gw2] [ 51%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_with_enum_type[totp]
src/tests/test_manager_list_entries.py::test_show_entry_details_with_enum_type[key_value]
[gw1] [ 52%] PASSED src/tests/test_archive_restore.py::test_view_archived_entries_view_only
src/tests/test_archive_restore.py::test_view_archived_entries_removed_after_restore
[gw2] [ 52%] PASSED src/tests/test_manager_list_entries.py::test_show_entry_details_with_enum_type[key_value]
src/tests/test_manager_retrieve_totp.py::test_handle_retrieve_totp_entry
[gw0] [ 52%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/fingerprint]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/nostr/pubkey]
[gw1] [ 52%] PASSED src/tests/test_archive_restore.py::test_view_archived_entries_removed_after_restore
src/tests/test_archive_restore.py::test_archived_entries_menu_hides_active
[gw2] [ 52%] PASSED src/tests/test_manager_retrieve_totp.py::test_handle_retrieve_totp_entry
src/tests/test_manager_search_display.py::test_search_entries_prompt_for_details
[gw1] [ 52%] PASSED src/tests/test_archive_restore.py::test_archived_entries_menu_hides_active
src/tests/test_atomic_write.py::test_atomic_write_concurrent
[gw2] [ 52%] PASSED src/tests/test_manager_search_display.py::test_search_entries_prompt_for_details
src/tests/test_manager_seed_setup.py::test_validate_bip85_seed_invalid_word
[gw2] [ 53%] PASSED src/tests/test_manager_seed_setup.py::test_validate_bip85_seed_invalid_word
src/tests/test_manager_seed_setup.py::test_validate_bip85_seed_checksum_failure
[gw2] [ 53%] PASSED src/tests/test_manager_seed_setup.py::test_validate_bip85_seed_checksum_failure
src/tests/test_manager_seed_setup.py::test_setup_existing_seed_words
[gw2] [ 53%] PASSED src/tests/test_manager_seed_setup.py::test_setup_existing_seed_words
src/tests/test_manager_seed_setup.py::test_setup_existing_seed_paste
[gw2] [ 53%] PASSED src/tests/test_manager_seed_setup.py::test_setup_existing_seed_paste
src/tests/test_manager_seed_setup.py::test_setup_existing_seed_with_args
[gw2] [ 53%] PASSED src/tests/test_manager_seed_setup.py::test_setup_existing_seed_with_args
src/tests/test_manager_warning_notifications.py::test_handle_search_entries_no_query
[gw2] [ 53%] PASSED src/tests/test_manager_warning_notifications.py::test_handle_search_entries_no_query
src/tests/test_manager_workflow.py::test_manager_workflow
[gw1] [ 54%] PASSED src/tests/test_atomic_write.py::test_atomic_write_concurrent
src/tests/test_audit_logger.py::test_audit_logger_records_events
[gw1] [ 54%] PASSED src/tests/test_audit_logger.py::test_audit_logger_records_events
src/tests/test_audit_logger.py::test_audit_log_tamper_evident
[gw1] [ 54%] PASSED src/tests/test_audit_logger.py::test_audit_log_tamper_evident
src/tests/test_auto_sync.py::test_auto_sync_triggers_post
[gw1] [ 54%] PASSED src/tests/test_auto_sync.py::test_auto_sync_triggers_post
src/tests/test_background_error_reporting.py::test_start_background_sync_error
[gw1] [ 54%] PASSED src/tests/test_background_error_reporting.py::test_start_background_sync_error
src/tests/test_background_error_reporting.py::test_start_background_relay_check_error
[gw1] [ 54%] PASSED src/tests/test_background_error_reporting.py::test_start_background_relay_check_error
src/tests/test_background_relay_check.py::test_background_relay_check_runs_async
[gw2] [ 54%] PASSED src/tests/test_manager_workflow.py::test_manager_workflow
src/tests/test_manifest_id_privacy.py::test_published_events_no_fingerprint
[gw2] [ 55%] PASSED src/tests/test_manifest_id_privacy.py::test_published_events_no_fingerprint
src/tests/test_manifest_state_restore.py::test_manifest_state_restored
[gw1] [ 55%] PASSED src/tests/test_background_relay_check.py::test_background_relay_check_runs_async
src/tests/test_background_relay_check.py::test_background_relay_check_warns_when_unhealthy
[gw1] [ 55%] PASSED src/tests/test_background_relay_check.py::test_background_relay_check_warns_when_unhealthy
src/tests/test_background_sync_always.py::test_switch_fingerprint_triggers_bg_sync
[gw1] [ 55%] PASSED src/tests/test_background_sync_always.py::test_switch_fingerprint_triggers_bg_sync
src/tests/test_background_sync_always.py::test_exit_managed_account_triggers_bg_sync
[gw1] [ 55%] PASSED src/tests/test_background_sync_always.py::test_exit_managed_account_triggers_bg_sync
src/tests/test_backup_interval.py::test_backup_interval
[gw2] [ 55%] PASSED src/tests/test_manifest_state_restore.py::test_manifest_state_restored
src/tests/test_memory_protection.py::test_inmemory_secret_round_trip_bytes_and_str
[gw2] [ 55%] PASSED src/tests/test_memory_protection.py::test_inmemory_secret_round_trip_bytes_and_str
src/tests/test_memory_protection.py::test_inmemory_secret_invalid_type
[gw2] [ 56%] PASSED src/tests/test_memory_protection.py::test_inmemory_secret_invalid_type
src/tests/test_memory_protection.py::test_inmemory_secret_wipe_clears_attributes
[gw2] [ 56%] PASSED src/tests/test_memory_protection.py::test_inmemory_secret_wipe_clears_attributes
src/tests/test_menu_navigation.py::test_navigate_all_main_menu_options
[gw2] [ 56%] PASSED src/tests/test_menu_navigation.py::test_navigate_all_main_menu_options
src/tests/test_menu_notifications.py::test_display_menu_prints_notifications
[gw2] [ 56%] PASSED src/tests/test_menu_notifications.py::test_display_menu_prints_notifications
src/tests/test_menu_notifications.py::test_display_menu_reuses_notification_line
[gw2] [ 56%] PASSED src/tests/test_menu_notifications.py::test_display_menu_reuses_notification_line
src/tests/test_menu_options.py::test_menu_totp_option
[gw2] [ 56%] PASSED src/tests/test_menu_options.py::test_menu_totp_option
src/tests/test_menu_options.py::test_menu_settings_option
[gw2] [ 57%] PASSED src/tests/test_menu_options.py::test_menu_settings_option
src/tests/test_menu_search.py::test_menu_search_option
[gw2] [ 57%] PASSED src/tests/test_menu_search.py::test_menu_search_option
src/tests/test_migrations.py::test_migrate_v0_to_v4
[gw1] [ 57%] PASSED src/tests/test_backup_interval.py::test_backup_interval
src/tests/test_backup_restore.py::test_backup_restore_workflow
[gw0] [ 57%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-get-/api/v1/nostr/pubkey]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/shutdown]
[gw2] [ 57%] PASSED src/tests/test_migrations.py::test_migrate_v0_to_v4
src/tests/test_migrations.py::test_migrate_v1_to_v4
[gw3] [ 57%] PASSED src/tests/test_fuzz_key_derivation.py::test_fuzz_key_round_trip
src/tests/test_generate_test_profile.py::test_initialize_profile_creates_directories
[gw1] [ 57%] PASSED src/tests/test_backup_restore.py::test_backup_restore_workflow
src/tests/test_backup_restore.py::test_additional_backup_location
[gw2] [ 58%] PASSED src/tests/test_migrations.py::test_migrate_v1_to_v4
src/tests/test_migrations.py::test_migrate_v2_to_v4
[gw1] [ 58%] PASSED src/tests/test_backup_restore.py::test_additional_backup_location
src/tests/test_backup_restore_startup.py::test_cli_flag_restores_before_init
[gw1] [ 58%] PASSED src/tests/test_backup_restore_startup.py::test_cli_flag_restores_before_init
src/tests/test_backup_restore_startup.py::test_menu_option_restores_before_init
[gw1] [ 58%] PASSED src/tests/test_backup_restore_startup.py::test_menu_option_restores_before_init
src/tests/test_bip85_derivation_path.py::test_derivation_paths_for_entropy_lengths
[gw1] [ 58%] PASSED src/tests/test_bip85_derivation_path.py::test_derivation_paths_for_entropy_lengths
src/tests/test_bip85_derivation_path.py::test_default_word_count_from_entropy_bytes
[gw1] [ 58%] PASSED src/tests/test_bip85_derivation_path.py::test_default_word_count_from_entropy_bytes
src/tests/test_bip85_init.py::test_init_with_seed_bytes
[gw1] [ 59%] PASSED src/tests/test_bip85_init.py::test_init_with_seed_bytes
src/tests/test_bip85_init.py::test_init_with_xprv
[gw1] [ 59%] PASSED src/tests/test_bip85_init.py::test_init_with_xprv
src/tests/test_modify_ssh_managed_entries.py::test_modify_ssh_entry
[gw2] [ 59%] PASSED src/tests/test_migrations.py::test_migrate_v2_to_v4
src/tests/test_migrations.py::test_error_on_future_version
[gw2] [ 59%] PASSED src/tests/test_migrations.py::test_error_on_future_version
src/tests/test_migrations.py::test_schema_migration_persisted_once
[gw1] [ 59%] PASSED src/tests/test_modify_ssh_managed_entries.py::test_modify_ssh_entry
src/tests/test_modify_ssh_managed_entries.py::test_modify_managed_account_entry
[gw2] [ 59%] PASSED src/tests/test_migrations.py::test_schema_migration_persisted_once
src/tests/test_nostr_client.py::test_check_relay_health_runs_async
[gw2] [ 59%] PASSED src/tests/test_nostr_client.py::test_check_relay_health_runs_async
src/tests/test_nostr_client.py::test_ping_relay_accepts_eose
[gw2] [ 60%] PASSED src/tests/test_nostr_client.py::test_ping_relay_accepts_eose
src/tests/test_nostr_client.py::test_update_relays_reinitializes_pool
[gw2] [ 60%] PASSED src/tests/test_nostr_client.py::test_update_relays_reinitializes_pool
src/tests/test_nostr_client.py::test_retrieve_json_sync_backoff
[gw3] [ 60%] PASSED src/tests/test_generate_test_profile.py::test_initialize_profile_creates_directories
[gw2] [ 60%] PASSED src/tests/test_nostr_client.py::test_retrieve_json_sync_backoff
src/tests/test_nostr_client.py::test_client_methods_run_in_event_loop
src/tests/test_generate_test_profile_sync.py::test_generate_test_profile_sync
[gw2] [ 60%] PASSED src/tests/test_nostr_client.py::test_client_methods_run_in_event_loop
src/tests/test_nostr_contract.py::test_publish_and_retrieve
[gw2] [ 60%] PASSED src/tests/test_nostr_contract.py::test_publish_and_retrieve
src/tests/test_nostr_dummy_client.py::test_manifest_generation
[gw1] [ 60%] PASSED src/tests/test_modify_ssh_managed_entries.py::test_modify_managed_account_entry
src/tests/test_modify_totp_entry.py::test_modify_totp_entry_period_digits_and_archive
[gw2] [ 61%] PASSED src/tests/test_nostr_dummy_client.py::test_manifest_generation
src/tests/test_nostr_dummy_client.py::test_retrieve_multi_chunk_snapshot
[gw2] [ 61%] PASSED src/tests/test_nostr_dummy_client.py::test_retrieve_multi_chunk_snapshot
src/tests/test_nostr_dummy_client.py::test_publish_and_fetch_deltas
[gw2] [ 61%] PASSED src/tests/test_nostr_dummy_client.py::test_publish_and_fetch_deltas
src/tests/test_nostr_dummy_client.py::test_fetch_snapshot_fallback_on_missing_chunk
[gw2] [ 61%] PASSED src/tests/test_nostr_dummy_client.py::test_fetch_snapshot_fallback_on_missing_chunk
src/tests/test_nostr_dummy_client.py::test_fetch_snapshot_uses_event_ids
[gw2] [ 61%] PASSED src/tests/test_nostr_dummy_client.py::test_fetch_snapshot_uses_event_ids
src/tests/test_nostr_dummy_client.py::test_publish_delta_aborts_if_outdated
[gw2] [ 61%] PASSED src/tests/test_nostr_dummy_client.py::test_publish_delta_aborts_if_outdated
src/tests/test_nostr_entry.py::test_nostr_key_determinism
[gw0] [ 62%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/shutdown]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/entry]
[gw1] [ 62%] PASSED src/tests/test_modify_totp_entry.py::test_modify_totp_entry_period_digits_and_archive
src/tests/test_modify_totp_entry.py::test_modify_totp_entry_invalid_field
[gw1] [ 62%] PASSED src/tests/test_modify_totp_entry.py::test_modify_totp_entry_invalid_field
src/tests/test_multiple_deltas_sync.py::test_sync_applies_multiple_deltas
[gw2] [ 62%] PASSED src/tests/test_nostr_entry.py::test_nostr_key_determinism
src/tests/test_nostr_index_size.py::test_nostr_index_size_limits
[gw2] [ 62%] SKIPPED src/tests/test_nostr_index_size.py::test_nostr_index_size_limits
src/tests/test_nostr_legacy_decrypt_fallback.py::test_legacy_password_only_fallback
[gw2] [ 62%] PASSED src/tests/test_nostr_legacy_decrypt_fallback.py::test_legacy_password_only_fallback
src/tests/test_nostr_legacy_key_fallback.py::test_fetch_snapshot_legacy_key_fallback
[gw2] [ 62%] PASSED src/tests/test_nostr_legacy_key_fallback.py::test_fetch_snapshot_legacy_key_fallback
src/tests/test_nostr_qr.py::test_show_qr_for_nostr_keys
[gw3] [ 63%] PASSED src/tests/test_generate_test_profile_sync.py::test_generate_test_profile_sync
src/tests/test_key_validation_failures.py::test_add_seed_validation_failure
[gw2] [ 63%] PASSED src/tests/test_nostr_qr.py::test_show_qr_for_nostr_keys
src/tests/test_nostr_qr.py::test_show_private_key_qr
[gw1] [ 63%] PASSED src/tests/test_multiple_deltas_sync.py::test_sync_applies_multiple_deltas
src/tests/test_multiple_deltas_sync.py::test_initial_sync_applies_multiple_deltas
[gw3] [ 63%] PASSED src/tests/test_key_validation_failures.py::test_add_seed_validation_failure
src/tests/test_key_validation_failures.py::test_add_managed_account_validation_failure
[gw2] [ 63%] PASSED src/tests/test_nostr_qr.py::test_show_private_key_qr
src/tests/test_nostr_qr.py::test_qr_menu_case_insensitive
[gw3] [ 63%] PASSED src/tests/test_key_validation_failures.py::test_add_managed_account_validation_failure
src/tests/test_key_value_entry.py::test_add_and_modify_key_value
[gw2] [ 63%] PASSED src/tests/test_nostr_qr.py::test_qr_menu_case_insensitive
src/tests/test_nostr_real.py::test_nostr_publish_and_retrieve
[gw2] [ 64%] SKIPPED src/tests/test_nostr_real.py::test_nostr_publish_and_retrieve
src/tests/test_nostr_restore_flow.py::test_restore_flow_from_snapshot
[gw1] [ 64%] PASSED src/tests/test_multiple_deltas_sync.py::test_initial_sync_applies_multiple_deltas
[gw3] [ 64%] PASSED src/tests/test_key_value_entry.py::test_add_and_modify_key_value
src/tests/test_multiple_fingerprint_prompt.py::test_prompt_when_multiple_fingerprints
src/tests/test_last_used_fingerprint.py::test_last_used_fingerprint
[gw1] [ 64%] PASSED src/tests/test_multiple_fingerprint_prompt.py::test_prompt_when_multiple_fingerprints
src/tests/test_new_seed_profile_creation.py::test_generate_new_seed_creates_profile
[gw3] [ 64%] PASSED src/tests/test_last_used_fingerprint.py::test_last_used_fingerprint
src/tests/test_legacy_format_exception.py::test_decrypt_data_raises_legacy_exception
[gw3] [ 64%] PASSED src/tests/test_legacy_format_exception.py::test_decrypt_data_raises_legacy_exception
src/tests/test_legacy_format_exception.py::test_vault_handles_legacy_exception
[gw1] [ 65%] PASSED src/tests/test_new_seed_profile_creation.py::test_generate_new_seed_creates_profile
src/tests/test_nonce_uniqueness.py::test_nonce_uniqueness
[gw1] [ 65%] PASSED src/tests/test_nonce_uniqueness.py::test_nonce_uniqueness
src/tests/test_noninteractive_init_unlock.py::test_init_with_password
[gw0] [ 65%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/entry]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-put-/api/v1/entry/1]
[gw2] [ 65%] PASSED src/tests/test_nostr_restore_flow.py::test_restore_flow_from_snapshot
src/tests/test_nostr_sdk_workflow.py::test_nostr_sdk_send_receive
[gw3] [ 65%] PASSED src/tests/test_legacy_format_exception.py::test_vault_handles_legacy_exception
src/tests/test_legacy_migration.py::test_legacy_index_migrates
[gw3] [ 65%] PASSED src/tests/test_legacy_migration.py::test_legacy_index_migrates
src/tests/test_legacy_migration.py::test_failed_migration_restores_legacy
[gw1] [ 65%] PASSED src/tests/test_noninteractive_init_unlock.py::test_init_with_password
src/tests/test_noninteractive_init_unlock.py::test_unlock_with_password
[gw3] [ 66%] PASSED src/tests/test_legacy_migration.py::test_failed_migration_restores_legacy
src/tests/test_legacy_migration.py::test_migrated_index_has_v3_prefix
[gw3] [ 66%] PASSED src/tests/test_legacy_migration.py::test_migrated_index_has_v3_prefix
src/tests/test_legacy_migration.py::test_legacy_index_migration_removes_strays
[gw2] [ 66%] PASSED src/tests/test_nostr_sdk_workflow.py::test_nostr_sdk_send_receive
src/tests/test_nostr_snapshot.py::test_prepare_snapshot_roundtrip
[gw2] [ 66%] PASSED src/tests/test_nostr_snapshot.py::test_prepare_snapshot_roundtrip
src/tests/test_nostr_snapshot.py::test_fetch_latest_snapshot
[gw2] [ 66%] PASSED src/tests/test_nostr_snapshot.py::test_fetch_latest_snapshot
src/tests/test_offline_mode_behavior.py::test_sync_vault_skips_network
[gw2] [ 66%] PASSED src/tests/test_offline_mode_behavior.py::test_sync_vault_skips_network
src/tests/test_offline_mode_behavior.py::test_start_background_sync_offline
[gw3] [ 67%] PASSED src/tests/test_legacy_migration.py::test_legacy_index_migration_removes_strays
src/tests/test_legacy_migration.py::test_migration_syncs_when_confirmed
[gw2] [ 67%] PASSED src/tests/test_offline_mode_behavior.py::test_start_background_sync_offline
src/tests/test_offline_mode_default_enabled.py::test_offline_mode_default_enabled
[gw0] [ 67%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-put-/api/v1/entry/1]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-put-/api/v1/config/inactivity_timeout]
[gw2] [ 67%] PASSED src/tests/test_offline_mode_default_enabled.py::test_offline_mode_default_enabled
src/tests/test_offline_mode_profile_creation.py::test_toggle_offline_mode_after_profile_creation
[gw3] [ 67%] PASSED src/tests/test_legacy_migration.py::test_migration_syncs_when_confirmed
src/tests/test_legacy_migration.py::test_migration_declines_sync
[gw1] [ 67%] PASSED src/tests/test_noninteractive_init_unlock.py::test_unlock_with_password
src/tests/test_nostr_backup.py::test_backup_and_publish_to_nostr
[gw2] [ 67%] PASSED src/tests/test_offline_mode_profile_creation.py::test_toggle_offline_mode_after_profile_creation
src/tests/test_parent_seed_backup.py::test_handle_backup_reveal_parent_seed_confirm
[gw2] [ 68%] PASSED src/tests/test_parent_seed_backup.py::test_handle_backup_reveal_parent_seed_confirm
src/tests/test_parent_seed_backup.py::test_handle_backup_reveal_parent_seed_cancel
[gw2] [ 68%] PASSED src/tests/test_parent_seed_backup.py::test_handle_backup_reveal_parent_seed_cancel
src/tests/test_parent_seed_backup.py::test_is_valid_filename
[gw2] [ 68%] PASSED src/tests/test_parent_seed_backup.py::test_is_valid_filename
src/tests/test_password_change.py::test_change_password_triggers_nostr_backup
[gw3] [ 68%] PASSED src/tests/test_legacy_migration.py::test_migration_declines_sync
src/tests/test_legacy_migration.py::test_legacy_nostr_payload_syncs_when_confirmed
[gw1] [ 68%] PASSED src/tests/test_nostr_backup.py::test_backup_and_publish_to_nostr
src/tests/test_nostr_client.py::test_nostr_client_uses_custom_relays
[gw1] [ 68%] PASSED src/tests/test_nostr_client.py::test_nostr_client_uses_custom_relays
src/tests/test_nostr_client.py::test_initialize_client_pool_add_relays_used
[gw1] [ 68%] PASSED src/tests/test_nostr_client.py::test_initialize_client_pool_add_relays_used
src/tests/test_nostr_client.py::test_initialize_client_pool_add_relay_fallback
[gw1] [ 69%] PASSED src/tests/test_nostr_client.py::test_initialize_client_pool_add_relay_fallback
src/tests/test_password_prompt.py::test_prompt_new_password_retry
[gw3] [ 69%] PASSED src/tests/test_legacy_migration.py::test_legacy_nostr_payload_syncs_when_confirmed
src/tests/test_legacy_migration.py::test_legacy_index_reinit_syncs_once_when_confirmed
[gw2] [ 69%] PASSED src/tests/test_password_change.py::test_change_password_triggers_nostr_backup
src/tests/test_password_generation_policy.py::test_zero_policy_preserves_length
[gw2] [ 69%] PASSED src/tests/test_password_generation_policy.py::test_zero_policy_preserves_length
src/tests/test_password_generation_policy.py::test_custom_policy_applied
[gw2] [ 69%] PASSED src/tests/test_password_generation_policy.py::test_custom_policy_applied
src/tests/test_password_generation_policy.py::test_generate_password_respects_policy
[gw3] [ 69%] PASSED src/tests/test_legacy_migration.py::test_legacy_index_reinit_syncs_once_when_confirmed
src/tests/test_legacy_migration.py::test_schema_migration_no_sync_prompt
[gw2] [ 70%] PASSED src/tests/test_password_generation_policy.py::test_generate_password_respects_policy
src/tests/test_password_helpers.py::test_derive_password_entropy_length
[gw3] [ 70%] PASSED src/tests/test_legacy_migration.py::test_schema_migration_no_sync_prompt
src/tests/test_legacy_migration.py::test_declined_migration_no_sync_prompt
[gw2] [ 70%] PASSED src/tests/test_password_helpers.py::test_derive_password_entropy_length
src/tests/test_password_helpers.py::test_map_entropy_to_chars_only_uses_alphabet
[gw2] [ 70%] PASSED src/tests/test_password_helpers.py::test_map_entropy_to_chars_only_uses_alphabet
src/tests/test_password_helpers.py::test_enforce_complexity_minimum_counts
[gw3] [ 70%] PASSED src/tests/test_legacy_migration.py::test_declined_migration_no_sync_prompt
[gw2] [ 70%] PASSED src/tests/test_password_helpers.py::test_enforce_complexity_minimum_counts
src/tests/test_legacy_migration.py::test_failed_migration_no_sync_prompt
src/tests/test_password_helpers.py::test_shuffle_deterministically_repeatable
[gw2] [ 70%] PASSED src/tests/test_password_helpers.py::test_shuffle_deterministically_repeatable
src/tests/test_password_length_constraints.py::test_generate_password_too_short_raises
[gw2] [ 71%] PASSED src/tests/test_password_length_constraints.py::test_generate_password_too_short_raises
src/tests/test_password_notes_display.py::test_password_notes_shown
[gw0] [ 71%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-put-/api/v1/config/inactivity_timeout]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/entry/1/archive]
[gw3] [ 71%] PASSED src/tests/test_legacy_migration.py::test_failed_migration_no_sync_prompt
src/tests/test_legacy_migration_iterations.py::test_migrate_iterations[50000]
[gw2] [ 71%] PASSED src/tests/test_password_notes_display.py::test_password_notes_shown
src/tests/test_password_prompt.py::test_prompt_new_password
[gw2] [ 71%] PASSED src/tests/test_password_prompt.py::test_prompt_new_password
src/tests/test_password_special_modes.py::test_enforce_complexity_min_special_zero
[gw2] [ 71%] PASSED src/tests/test_password_special_modes.py::test_enforce_complexity_min_special_zero
src/tests/test_password_unlock_after_change.py::test_password_change_and_unlock
[gw3] [ 72%] PASSED src/tests/test_legacy_migration_iterations.py::test_migrate_iterations[50000]
src/tests/test_legacy_migration_iterations.py::test_migrate_iterations[100000]
[gw3] [ 72%] PASSED src/tests/test_legacy_migration_iterations.py::test_migrate_iterations[100000]
src/tests/test_legacy_migration_prompt.py::test_open_legacy_without_migrating
[gw3] [ 72%] PASSED src/tests/test_legacy_migration_prompt.py::test_open_legacy_without_migrating
src/tests/test_legacy_migration_prompt.py::test_migrate_legacy_sets_flag
[gw3] [ 72%] PASSED src/tests/test_legacy_migration_prompt.py::test_migrate_legacy_sets_flag
src/tests/test_legacy_migration_second_session.py::test_legacy_migration_second_session
[gw1] [ 72%] PASSED src/tests/test_password_prompt.py::test_prompt_new_password_retry
src/tests/test_password_prompt.py::test_prompt_existing_password
[gw1] [ 72%] PASSED src/tests/test_password_prompt.py::test_prompt_existing_password
src/tests/test_password_prompt.py::test_confirm_action_yes_no
[gw1] [ 72%] PASSED src/tests/test_password_prompt.py::test_confirm_action_yes_no
src/tests/test_password_properties.py::test_password_properties
[gw3] [ 73%] PASSED src/tests/test_legacy_migration_second_session.py::test_legacy_migration_second_session
src/tests/test_list_entries_all_types.py::test_cli_list_all_types
[gw0] [ 73%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/entry/1/archive]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/entry/1/unarchive]
[gw3] [ 73%] PASSED src/tests/test_list_entries_all_types.py::test_cli_list_all_types
src/tests/test_list_entries_all_types.py::test_menu_list_all_types
[gw3] [ 73%] PASSED src/tests/test_list_entries_all_types.py::test_menu_list_all_types
src/tests/test_list_entries_sort_filter.py::test_sort_by_label
[gw3] [ 73%] PASSED src/tests/test_list_entries_sort_filter.py::test_sort_by_label
src/tests/test_portable_backup.py::test_export_creates_additional_backup_and_import
[gw3] [ 73%] PASSED src/tests/test_portable_backup.py::test_export_creates_additional_backup_and_import
src/tests/test_post_sync_messages.py::test_handle_post_success
[gw3] [ 73%] PASSED src/tests/test_post_sync_messages.py::test_handle_post_success
src/tests/test_post_sync_messages.py::test_handle_post_failure
[gw3] [ 74%] PASSED src/tests/test_post_sync_messages.py::test_handle_post_failure
src/tests/test_post_sync_messages.py::test_handle_post_prints_all_ids
[gw3] [ 74%] PASSED src/tests/test_post_sync_messages.py::test_handle_post_prints_all_ids
src/tests/test_profile_cleanup.py::test_generate_seed_cleanup_on_failure
[gw3] [ 74%] PASSED src/tests/test_profile_cleanup.py::test_generate_seed_cleanup_on_failure
src/tests/test_profile_deletion_sync.py::test_profile_deletion_stops_sync
[gw3] [ 74%] PASSED src/tests/test_profile_deletion_sync.py::test_profile_deletion_stops_sync
src/tests/test_profile_export_import.py::test_profile_export_import_round_trip
[gw0] [ 74%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/entry/1/unarchive]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/change-password]
[gw3] [ 74%] PASSED src/tests/test_profile_export_import.py::test_profile_export_import_round_trip
src/tests/test_profile_init_integration.py::test_initialize_profile_and_manager
[gw2] [ 75%] PASSED src/tests/test_password_unlock_after_change.py::test_password_change_and_unlock
src/tests/test_pgp_entry.py::test_pgp_key_determinism
[gw0] [ 75%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/change-password]
src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/vault/lock]
[gw2] [ 75%] PASSED src/tests/test_pgp_entry.py::test_pgp_key_determinism
src/tests/test_pgp_entry.py::test_pgp_rsa_key_determinism
[gw3] [ 75%] PASSED src/tests/test_profile_init_integration.py::test_initialize_profile_and_manager
src/tests/test_profile_management.py::test_add_and_delete_entry
[gw3] [ 75%] PASSED src/tests/test_profile_management.py::test_add_and_delete_entry
src/tests/test_profiles.py::test_add_and_switch_fingerprint
[gw3] [ 75%] PASSED src/tests/test_profiles.py::test_add_and_switch_fingerprint
src/tests/test_profiles.py::test_sync_index_missing_bad_data
[gw3] [ 75%] PASSED src/tests/test_profiles.py::test_sync_index_missing_bad_data
src/tests/test_profiles.py::test_attempt_initial_sync_incomplete_data
[gw3] [ 76%] PASSED src/tests/test_profiles.py::test_attempt_initial_sync_incomplete_data
src/tests/test_publish_json_result.py::test_publish_snapshot_success
[gw3] [ 76%] PASSED src/tests/test_publish_json_result.py::test_publish_snapshot_success
src/tests/test_publish_json_result.py::test_publish_snapshot_failure
[gw3] [ 76%] PASSED src/tests/test_publish_json_result.py::test_publish_snapshot_failure
src/tests/test_pubsub.py::test_subscribe_and_publish
[gw3] [ 76%] PASSED src/tests/test_pubsub.py::test_subscribe_and_publish
src/tests/test_pubsub.py::test_unsubscribe
[gw3] [ 76%] PASSED src/tests/test_pubsub.py::test_unsubscribe
src/tests/test_quick_unlock_default.py::test_quick_unlock_default_off
[gw3] [ 76%] PASSED src/tests/test_quick_unlock_default.py::test_quick_unlock_default_off
src/tests/test_quick_unlock_default.py::test_quick_unlock_logs_event
[gw3] [ 77%] PASSED src/tests/test_quick_unlock_default.py::test_quick_unlock_logs_event
src/tests/test_quick_unlock_profile_creation.py::test_toggle_quick_unlock_after_profile_creation
[gw0] [ 77%] PASSED src/tests/test_api.py::test_invalid_token_other_endpoints[asyncio-post-/api/v1/vault/lock]
src/tests/test_api_new_endpoints.py::test_create_and_modify_totp_entry[asyncio]
[gw3] [ 77%] PASSED src/tests/test_quick_unlock_profile_creation.py::test_toggle_quick_unlock_after_profile_creation
src/tests/test_restore_from_nostr_setup.py::test_handle_new_seed_setup_restore_from_nostr
[gw3] [ 77%] PASSED src/tests/test_restore_from_nostr_setup.py::test_handle_new_seed_setup_restore_from_nostr
src/tests/test_restore_from_nostr_setup.py::test_handle_new_seed_setup_restore_from_local_backup
[gw3] [ 77%] PASSED src/tests/test_restore_from_nostr_setup.py::test_handle_new_seed_setup_restore_from_local_backup
src/tests/test_restore_from_nostr_setup.py::test_restore_from_nostr_warns
[gw0] [ 77%] PASSED src/tests/test_api_new_endpoints.py::test_create_and_modify_totp_entry[asyncio]
src/tests/test_api_new_endpoints.py::test_create_and_modify_ssh_entry[asyncio]
[gw3] [ 77%] PASSED src/tests/test_restore_from_nostr_setup.py::test_restore_from_nostr_warns
src/tests/test_restore_from_nostr_setup.py::test_restore_from_nostr_abort
[gw0] [ 78%] PASSED src/tests/test_api_new_endpoints.py::test_create_and_modify_ssh_entry[asyncio]
src/tests/test_api_new_endpoints.py::test_update_entry_error[asyncio]
[gw3] [ 78%] PASSED src/tests/test_restore_from_nostr_setup.py::test_restore_from_nostr_abort
src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-True0]
[gw3] [ 78%] PASSED src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-True0]
src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-True1]
[gw3] [ 78%] PASSED src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-True1]
src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-True2]
[gw0] [ 78%] PASSED src/tests/test_api_new_endpoints.py::test_update_entry_error[asyncio]
src/tests/test_api_new_endpoints.py::test_update_config_secret_mode[asyncio]
[gw3] [ 78%] PASSED src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-True2]
src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-False]
[gw3] [ 78%] PASSED src/tests/test_retrieve_pause_sensitive_entries.py::test_pause_before_entry_actions[<lambda>-False]
src/tests/test_search_entries.py::test_search_by_website
[gw3] [ 79%] PASSED src/tests/test_search_entries.py::test_search_by_website
src/tests/test_search_entries.py::test_search_by_username
[gw2] [ 79%] PASSED src/tests/test_pgp_entry.py::test_pgp_rsa_key_determinism
src/tests/test_portable_backup.py::test_round_trip
[gw3] [ 79%] PASSED src/tests/test_search_entries.py::test_search_by_username
src/tests/test_search_entries.py::test_search_by_url
[gw2] [ 79%] PASSED src/tests/test_portable_backup.py::test_round_trip
src/tests/test_portable_backup.py::test_round_trip_unencrypted
[gw3] [ 79%] PASSED src/tests/test_search_entries.py::test_search_by_url
src/tests/test_search_entries.py::test_search_by_notes_and_totp
[gw2] [ 79%] PASSED src/tests/test_portable_backup.py::test_round_trip_unencrypted
src/tests/test_portable_backup.py::test_corruption_detection
[gw3] [ 80%] PASSED src/tests/test_search_entries.py::test_search_by_notes_and_totp
src/tests/test_search_entries.py::test_search_by_custom_field
[gw2] [ 80%] PASSED src/tests/test_portable_backup.py::test_corruption_detection
src/tests/test_portable_backup.py::test_import_over_existing
[gw3] [ 80%] PASSED src/tests/test_search_entries.py::test_search_by_custom_field
src/tests/test_search_entries.py::test_search_key_value_value
[gw0] [ 80%] PASSED src/tests/test_api_new_endpoints.py::test_update_config_secret_mode[asyncio]
[gw2] [ 80%] PASSED src/tests/test_portable_backup.py::test_import_over_existing
src/tests/test_portable_backup.py::test_checksum_mismatch_detection
src/tests/test_api_new_endpoints.py::test_totp_export_endpoint[asyncio]
[gw3] [ 80%] PASSED src/tests/test_search_entries.py::test_search_key_value_value
src/tests/test_search_entries.py::test_search_no_results
[gw2] [ 80%] PASSED src/tests/test_portable_backup.py::test_checksum_mismatch_detection
src/tests/test_portable_backup.py::test_export_import_seed_encrypted_with_different_key
[gw3] [ 81%] PASSED src/tests/test_search_entries.py::test_search_no_results
src/tests/test_search_entries.py::test_search_by_tag_password
[gw2] [ 81%] PASSED src/tests/test_portable_backup.py::test_export_import_seed_encrypted_with_different_key
src/tests/test_seed_import.py::test_seed_encryption_round_trip
[gw3] [ 81%] PASSED src/tests/test_search_entries.py::test_search_by_tag_password
src/tests/test_search_entries.py::test_search_by_tag_totp
[gw2] [ 81%] PASSED src/tests/test_seed_import.py::test_seed_encryption_round_trip
src/tests/test_seed_migration.py::test_parent_seed_migrates_from_fernet
[gw3] [ 81%] PASSED src/tests/test_search_entries.py::test_search_by_tag_totp
src/tests/test_search_entries.py::test_search_with_kind_filter
[gw2] [ 81%] PASSED src/tests/test_seed_migration.py::test_parent_seed_migrates_from_fernet
src/tests/test_seed_prompt.py::test_masked_input_posix_backspace
[gw2] [ 81%] PASSED src/tests/test_seed_prompt.py::test_masked_input_posix_backspace
src/tests/test_seed_prompt.py::test_masked_input_windows_space
[gw2] [ 82%] PASSED src/tests/test_seed_prompt.py::test_masked_input_windows_space
src/tests/test_seed_prompt.py::test_masked_input_posix_ctrl_c
[gw2] [ 82%] PASSED src/tests/test_seed_prompt.py::test_masked_input_posix_ctrl_c
src/tests/test_seed_prompt.py::test_masked_input_windows_ctrl_c
[gw2] [ 82%] PASSED src/tests/test_seed_prompt.py::test_masked_input_windows_ctrl_c
src/tests/test_seed_prompt.py::test_prompt_seed_words_valid
[gw2] [ 82%] PASSED src/tests/test_seed_prompt.py::test_prompt_seed_words_valid
src/tests/test_seed_prompt.py::test_prompt_seed_words_invalid_word
[gw3] [ 82%] PASSED src/tests/test_search_entries.py::test_search_with_kind_filter
src/tests/test_secret_mode.py::test_password_retrieve_secret_mode
[gw3] [ 82%] PASSED src/tests/test_secret_mode.py::test_password_retrieve_secret_mode
src/tests/test_secret_mode.py::test_totp_display_secret_mode
[gw3] [ 83%] PASSED src/tests/test_secret_mode.py::test_totp_display_secret_mode
src/tests/test_secret_mode.py::test_password_retrieve_no_secret_mode
[gw0] [ 83%] PASSED src/tests/test_api_new_endpoints.py::test_totp_export_endpoint[asyncio]
src/tests/test_api_new_endpoints.py::test_totp_codes_endpoint[asyncio]
[gw3] [ 83%] PASSED src/tests/test_secret_mode.py::test_password_retrieve_no_secret_mode
src/tests/test_secret_mode.py::test_totp_display_no_secret_mode
[gw3] [ 83%] PASSED src/tests/test_secret_mode.py::test_totp_display_no_secret_mode
src/tests/test_secret_mode_profile_creation.py::test_add_new_fingerprint_initializes_managers
[gw3] [ 83%] PASSED src/tests/test_secret_mode_profile_creation.py::test_add_new_fingerprint_initializes_managers
src/tests/test_secret_mode_profile_creation.py::test_toggle_secret_mode_after_profile_creation
[gw3] [ 83%] PASSED src/tests/test_secret_mode_profile_creation.py::test_toggle_secret_mode_after_profile_creation
src/tests/test_seed_entry.py::test_seed_phrase_determinism
[gw3] [ 83%] PASSED src/tests/test_seed_entry.py::test_seed_phrase_determinism
src/tests/test_seed_generation.py::test_generate_bip85_and_new_seed
[gw3] [ 84%] PASSED src/tests/test_seed_generation.py::test_generate_bip85_and_new_seed
src/tests/test_settings_menu.py::test_relay_and_profile_actions
[gw3] [ 84%] PASSED src/tests/test_settings_menu.py::test_relay_and_profile_actions
src/tests/test_settings_menu.py::test_settings_menu_additional_backup
[gw3] [ 84%] PASSED src/tests/test_settings_menu.py::test_settings_menu_additional_backup
src/tests/test_settings_menu.py::test_settings_menu_change_password
[gw3] [ 84%] PASSED src/tests/test_settings_menu.py::test_settings_menu_change_password
src/tests/test_settings_menu.py::test_settings_menu_change_password_incorrect
[gw0] [ 84%] PASSED src/tests/test_api_new_endpoints.py::test_totp_codes_endpoint[asyncio]
src/tests/test_api_new_endpoints.py::test_parent_seed_endpoint_removed[asyncio]
[gw2] [ 84%] PASSED src/tests/test_seed_prompt.py::test_prompt_seed_words_invalid_word
src/tests/test_seed_word_by_word_flow.py::test_prompt_seed_words_confirmation_loop
[gw2] [ 85%] PASSED src/tests/test_seed_word_by_word_flow.py::test_prompt_seed_words_confirmation_loop
src/tests/test_seed_word_by_word_flow.py::test_prompt_seed_words_invalid_word
[gw2] [ 85%] PASSED src/tests/test_seed_word_by_word_flow.py::test_prompt_seed_words_invalid_word
src/tests/test_seed_word_by_word_flow.py::test_add_new_fingerprint_words_flow_success
[gw2] [ 85%] PASSED src/tests/test_seed_word_by_word_flow.py::test_add_new_fingerprint_words_flow_success
src/tests/test_seed_word_by_word_flow.py::test_add_new_fingerprint_words_flow_invalid_phrase
[gw2] [ 85%] PASSED src/tests/test_seed_word_by_word_flow.py::test_add_new_fingerprint_words_flow_invalid_phrase
src/tests/test_seedqr_encoding.py::test_seedqr_standard_example
[gw2] [ 85%] PASSED src/tests/test_seedqr_encoding.py::test_seedqr_standard_example
src/tests/test_service_classes.py::test_entry_service_add_password
[gw3] [ 85%] PASSED src/tests/test_settings_menu.py::test_settings_menu_change_password_incorrect
src/tests/test_settings_menu.py::test_settings_menu_without_nostr_client
[gw3] [ 85%] PASSED src/tests/test_settings_menu.py::test_settings_menu_without_nostr_client
src/tests/test_ssh_entry.py::test_add_and_retrieve_ssh_key_pair
[gw2] [ 86%] PASSED src/tests/test_service_classes.py::test_entry_service_add_password
src/tests/test_service_classes.py::test_menu_handler_list_entries
[gw3] [ 86%] PASSED src/tests/test_ssh_entry.py::test_add_and_retrieve_ssh_key_pair
src/tests/test_ssh_entry_valid.py::test_ssh_private_key_corresponds_to_public
[gw2] [ 86%] PASSED src/tests/test_service_classes.py::test_menu_handler_list_entries
src/tests/test_service_classes.py::test_profile_service_switch
[gw2] [ 86%] PASSED src/tests/test_service_classes.py::test_profile_service_switch
src/tests/test_stats_screen.py::test_stats_display_resets_after_exit
[gw2] [ 86%] PASSED src/tests/test_stats_screen.py::test_stats_display_resets_after_exit
src/tests/test_stats_screen.py::test_stats_screen_breaks_on_enter
[gw2] [ 86%] PASSED src/tests/test_stats_screen.py::test_stats_screen_breaks_on_enter
src/tests/test_sync_race_conditions.py::test_sync_race_conditions
[gw3] [ 86%] PASSED src/tests/test_ssh_entry_valid.py::test_ssh_private_key_corresponds_to_public
src/tests/test_state_manager.py::test_state_manager_round_trip
[gw3] [ 87%] PASSED src/tests/test_state_manager.py::test_state_manager_round_trip
src/tests/test_stats_screen.py::test_live_stats_shows_message
[gw3] [ 87%] PASSED src/tests/test_stats_screen.py::test_live_stats_shows_message
src/tests/test_stats_screen.py::test_live_stats_shows_notification
[gw3] [ 87%] PASSED src/tests/test_stats_screen.py::test_live_stats_shows_notification
src/tests/test_stats_screen.py::test_live_stats_triggers_background_sync
[gw3] [ 87%] PASSED src/tests/test_stats_screen.py::test_live_stats_triggers_background_sync
src/tests/test_stats_screen.py::test_stats_display_only_once
[gw3] [ 87%] PASSED src/tests/test_stats_screen.py::test_stats_display_only_once
src/tests/test_terminal_utils_failure_handling.py::test_format_profile_reraises
[gw3] [ 87%] PASSED src/tests/test_terminal_utils_failure_handling.py::test_format_profile_reraises
src/tests/test_terminal_utils_failure_handling.py::test_clear_header_with_notification_reraises
[gw3] [ 88%] PASSED src/tests/test_terminal_utils_failure_handling.py::test_clear_header_with_notification_reraises
src/tests/test_totp.py::test_current_code_matches_pyotp
[gw0] [ 88%] PASSED src/tests/test_api_new_endpoints.py::test_parent_seed_endpoint_removed[asyncio]
src/tests/test_api_new_endpoints.py::test_fingerprint_endpoints[asyncio]
[gw3] [ 88%] PASSED src/tests/test_totp.py::test_current_code_matches_pyotp
src/tests/test_totp.py::test_time_remaining
[gw3] [ 88%] PASSED src/tests/test_totp.py::test_time_remaining
[gw2] [ 88%] PASSED src/tests/test_sync_race_conditions.py::test_sync_race_conditions
src/tests/test_tag_persistence.py::test_tags_persist_on_new_entry
src/tests/test_totp.py::test_print_progress_bar_terminates
[gw3] [ 88%] PASSED src/tests/test_totp.py::test_print_progress_bar_terminates
src/tests/test_totp_entry.py::test_add_totp_and_get_code
[gw3] [ 88%] PASSED src/tests/test_totp_entry.py::test_add_totp_and_get_code
src/tests/test_totp_entry.py::test_totp_time_remaining
[gw2] [ 89%] PASSED src/tests/test_tag_persistence.py::test_tags_persist_on_new_entry
src/tests/test_tag_persistence.py::test_tags_persist_after_modify
[gw3] [ 89%] PASSED src/tests/test_totp_entry.py::test_totp_time_remaining
src/tests/test_totp_entry.py::test_add_totp_imported
[gw3] [ 89%] PASSED src/tests/test_totp_entry.py::test_add_totp_imported
src/tests/test_totp_entry.py::test_add_totp_with_notes
[gw2] [ 89%] PASSED src/tests/test_tag_persistence.py::test_tags_persist_after_modify
src/tests/test_totp_uri.py::test_parse_otpauth_missing_prefix
[gw2] [ 89%] PASSED src/tests/test_totp_uri.py::test_parse_otpauth_missing_prefix
src/tests/test_totp_uri.py::test_parse_otpauth_missing_secret
[gw2] [ 89%] PASSED src/tests/test_totp_uri.py::test_parse_otpauth_missing_secret
src/tests/test_totp_uri.py::test_make_otpauth_uri_roundtrip
[gw2] [ 90%] PASSED src/tests/test_totp_uri.py::test_make_otpauth_uri_roundtrip
src/tests/test_typer_cli.py::test_entry_list
[gw3] [ 90%] PASSED src/tests/test_totp_entry.py::test_add_totp_with_notes
src/tests/test_totp_entry.py::test_legacy_deterministic_entry
[gw2] [ 90%] PASSED src/tests/test_typer_cli.py::test_entry_list
src/tests/test_typer_cli.py::test_entry_search
[gw2] [ 90%] PASSED src/tests/test_typer_cli.py::test_entry_search
src/tests/test_typer_cli.py::test_entry_get_password
[gw2] [ 90%] PASSED src/tests/test_typer_cli.py::test_entry_get_password
src/tests/test_typer_cli.py::test_vault_export
[gw3] [ 90%] PASSED src/tests/test_totp_entry.py::test_legacy_deterministic_entry
[gw2] [ 90%] PASSED src/tests/test_typer_cli.py::test_vault_export
src/tests/test_typer_cli.py::test_vault_import
src/tests/test_totp_uri.py::test_parse_otpauth_normal
[gw3] [ 91%] PASSED src/tests/test_totp_uri.py::test_parse_otpauth_normal
src/tests/test_typer_cli.py::test_vault_change_password
[gw2] [ 91%] PASSED src/tests/test_typer_cli.py::test_vault_import
[gw3] [ 91%] PASSED src/tests/test_typer_cli.py::test_vault_change_password
src/tests/test_typer_cli.py::test_vault_import_triggers_sync
src/tests/test_typer_cli.py::test_vault_lock
[gw3] [ 91%] PASSED src/tests/test_typer_cli.py::test_vault_lock
src/tests/test_typer_cli.py::test_root_lock
[gw2] [ 91%] PASSED src/tests/test_typer_cli.py::test_vault_import_triggers_sync
src/tests/test_typer_cli.py::test_nostr_get_pubkey
[gw3] [ 91%] PASSED src/tests/test_typer_cli.py::test_root_lock
[gw2] [ 91%] PASSED src/tests/test_typer_cli.py::test_nostr_get_pubkey
src/tests/test_typer_cli.py::test_vault_reveal_parent_seed
src/tests/test_typer_cli.py::test_fingerprint_list
[gw2] [ 92%] PASSED src/tests/test_typer_cli.py::test_fingerprint_list
src/tests/test_typer_cli.py::test_fingerprint_add
[gw3] [ 92%] PASSED src/tests/test_typer_cli.py::test_vault_reveal_parent_seed
src/tests/test_typer_cli.py::test_fingerprint_remove
[gw2] [ 92%] PASSED src/tests/test_typer_cli.py::test_fingerprint_add
[gw3] [ 92%] PASSED src/tests/test_typer_cli.py::test_fingerprint_remove
src/tests/test_typer_cli.py::test_fingerprint_switch
src/tests/test_typer_cli.py::test_config_set
[gw3] [ 92%] PASSED src/tests/test_typer_cli.py::test_fingerprint_switch
[gw2] [ 92%] PASSED src/tests/test_typer_cli.py::test_config_set
src/tests/test_typer_cli.py::test_config_set_unknown_key
src/tests/test_typer_cli.py::test_config_get
[gw3] [ 93%] PASSED src/tests/test_typer_cli.py::test_config_get
src/tests/test_typer_cli.py::test_generate_password
[gw2] [ 93%] PASSED src/tests/test_typer_cli.py::test_config_set_unknown_key
src/tests/test_typer_cli.py::test_nostr_sync
[gw3] [ 93%] PASSED src/tests/test_typer_cli.py::test_generate_password
[gw2] [ 93%] PASSED src/tests/test_typer_cli.py::test_nostr_sync
src/tests/test_typer_cli.py::test_api_start_passes_fingerprint
src/tests/test_typer_cli.py::test_entry_list_passes_fingerprint
[gw3] [ 93%] PASSED src/tests/test_typer_cli.py::test_api_start_passes_fingerprint
[gw2] [ 93%] PASSED src/tests/test_typer_cli.py::test_entry_list_passes_fingerprint
src/tests/test_typer_cli.py::test_entry_modify
src/tests/test_typer_cli.py::test_entry_add
[gw3] [ 93%] PASSED src/tests/test_typer_cli.py::test_entry_modify
src/tests/test_typer_cli.py::test_entry_modify_invalid
[gw2] [ 94%] PASSED src/tests/test_typer_cli.py::test_entry_add
src/tests/test_typer_cli.py::test_entry_archive
[gw3] [ 94%] PASSED src/tests/test_typer_cli.py::test_entry_modify_invalid
src/tests/test_typer_cli.py::test_entry_unarchive
[gw2] [ 94%] PASSED src/tests/test_typer_cli.py::test_entry_archive
src/tests/test_typer_cli.py::test_entry_export_totp
[gw3] [ 94%] PASSED src/tests/test_typer_cli.py::test_entry_unarchive
src/tests/test_typer_cli.py::test_entry_totp_codes
[gw2] [ 94%] PASSED src/tests/test_typer_cli.py::test_entry_export_totp
src/tests/test_typer_cli.py::test_verify_checksum_command
[gw3] [ 94%] PASSED src/tests/test_typer_cli.py::test_entry_totp_codes
src/tests/test_typer_cli.py::test_update_checksum_command
[gw2] [ 95%] PASSED src/tests/test_typer_cli.py::test_verify_checksum_command
src/tests/test_typer_cli.py::test_tui_forward_fingerprint
[gw3] [ 95%] PASSED src/tests/test_typer_cli.py::test_update_checksum_command
src/tests/test_typer_cli.py::test_gui_command
[gw2] [ 95%] PASSED src/tests/test_typer_cli.py::test_tui_forward_fingerprint
src/tests/test_typer_cli.py::test_gui_command_no_backend
[gw3] [ 95%] PASSED src/tests/test_typer_cli.py::test_gui_command
src/tests/test_typer_cli.py::test_gui_command_install_backend
[gw2] [ 95%] PASSED src/tests/test_typer_cli.py::test_gui_command_no_backend
src/tests/test_unlock_sync.py::test_unlock_triggers_sync
[gw3] [ 95%] PASSED src/tests/test_typer_cli.py::test_gui_command_install_backend
src/tests/test_unlock_sync.py::test_quick_unlock_background_sync
[gw3] [ 95%] PASSED src/tests/test_unlock_sync.py::test_quick_unlock_background_sync
src/tests/test_v2_prefix_fallback.py::test_v2_prefix_fernet_fallback
[gw3] [ 96%] PASSED src/tests/test_v2_prefix_fallback.py::test_v2_prefix_fernet_fallback
src/tests/test_v2_prefix_fallback.py::test_aesgcm_payload_too_short
[gw3] [ 96%] PASSED src/tests/test_v2_prefix_fallback.py::test_aesgcm_payload_too_short
src/tests/test_vault_initialization.py::test_save_and_encrypt_seed_initializes_vault
[gw2] [ 96%] PASSED src/tests/test_unlock_sync.py::test_unlock_triggers_sync
src/tests/test_unlock_sync.py::test_start_background_sync_running_loop
[gw2] [ 96%] PASSED src/tests/test_unlock_sync.py::test_start_background_sync_running_loop
src/tests/test_vault_lock_flag.py::test_lock_vault_sets_flag_and_keeps_objects
[gw2] [ 96%] PASSED src/tests/test_vault_lock_flag.py::test_lock_vault_sets_flag_and_keeps_objects
src/tests/test_vault_lock_flag.py::test_entry_service_requires_unlocked
[gw2] [ 96%] PASSED src/tests/test_vault_lock_flag.py::test_entry_service_requires_unlocked
src/tests/test_vault_lock_flag.py::test_unlock_vault_clears_locked_flag
[gw2] [ 96%] PASSED src/tests/test_vault_lock_flag.py::test_unlock_vault_clears_locked_flag
src/tests/test_verbose_timing.py::test_unlock_vault_logs_time
[gw2] [ 97%] PASSED src/tests/test_verbose_timing.py::test_unlock_vault_logs_time
src/tests/test_verbose_timing.py::test_publish_snapshot_logs_time
[gw2] [ 97%] PASSED src/tests/test_verbose_timing.py::test_publish_snapshot_logs_time
tests/perf/test_bip85_cache.py::test_bip85_cache_benchmark
[gw2] [ 97%] PASSED tests/perf/test_bip85_cache.py::test_bip85_cache_benchmark
[gw0] [ 97%] PASSED src/tests/test_api_new_endpoints.py::test_fingerprint_endpoints[asyncio]
src/tests/test_api_new_endpoints.py::test_checksum_endpoints[asyncio]
[gw3] [ 97%] PASSED src/tests/test_vault_initialization.py::test_save_and_encrypt_seed_initializes_vault
src/tests/test_vault_lock_event.py::test_lock_vault_publishes_event
[gw3] [ 97%] PASSED src/tests/test_vault_lock_event.py::test_lock_vault_publishes_event
[gw0] [ 98%] PASSED src/tests/test_api_new_endpoints.py::test_checksum_endpoints[asyncio]
src/tests/test_api_new_endpoints.py::test_vault_import_via_path[asyncio]
[gw0] [ 98%] PASSED src/tests/test_api_new_endpoints.py::test_vault_import_via_path[asyncio]
src/tests/test_api_new_endpoints.py::test_vault_import_via_upload[asyncio]
[gw0] [ 98%] PASSED src/tests/test_api_new_endpoints.py::test_vault_import_via_upload[asyncio]
src/tests/test_api_new_endpoints.py::test_vault_import_invalid_extension[asyncio]
[gw0] [ 98%] PASSED src/tests/test_api_new_endpoints.py::test_vault_import_invalid_extension[asyncio]
src/tests/test_api_new_endpoints.py::test_vault_import_path_traversal_blocked[asyncio]
[gw0] [ 98%] PASSED src/tests/test_api_new_endpoints.py::test_vault_import_path_traversal_blocked[asyncio]
[gw1] [ 98%] PASSED src/tests/test_password_properties.py::test_password_properties
src/tests/test_password_shuffle_consistency.py::test_password_generation_consistent_output
[gw1] [ 98%] PASSED src/tests/test_password_shuffle_consistency.py::test_password_generation_consistent_output
src/tests/test_password_special_chars.py::test_no_special_chars
[gw1] [ 99%] PASSED src/tests/test_password_special_chars.py::test_no_special_chars
src/tests/test_password_special_chars.py::test_allowed_special_chars_only
[gw1] [ 99%] PASSED src/tests/test_password_special_chars.py::test_allowed_special_chars_only
src/tests/test_password_special_chars.py::test_exclude_ambiguous_chars
[gw1] [ 99%] PASSED src/tests/test_password_special_chars.py::test_exclude_ambiguous_chars
src/tests/test_password_special_chars.py::test_safe_special_chars_mode
[gw1] [ 99%] PASSED src/tests/test_password_special_chars.py::test_safe_special_chars_mode
src/tests/test_password_special_modes.py::test_include_special_chars_false
[gw1] [ 99%] PASSED src/tests/test_password_special_modes.py::test_include_special_chars_false
src/tests/test_password_special_modes.py::test_safe_mode_uses_safe_chars
[gw1] [ 99%] PASSED src/tests/test_password_special_modes.py::test_safe_mode_uses_safe_chars
src/tests/test_password_special_modes.py::test_allowed_chars_override_special_mode
[gw1] [100%] PASSED src/tests/test_password_special_modes.py::test_allowed_chars_override_special_mode

=============================== warnings summary ===============================
../home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pgpy/constants.py:5
../home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pgpy/constants.py:5
../home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pgpy/constants.py:5
../home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pgpy/constants.py:5
../home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pgpy/constants.py:5
  /home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pgpy/constants.py:5: DeprecationWarning: 'imghdr' is deprecated and slated for removal in Python 3.13
    import imghdr

../home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/typer/params.py:206: 24 warnings
src/tests/test_cli_integration.py: 2 warnings
  /home/jules/.pyenv/versions/3.12.12/lib/python3.12/site-packages/typer/params.py:206: DeprecationWarning: The 'is_flag' and 'flag_value' parameters are not supported by Typer and will be removed entirely in a future release.
    return OptionInfo(

src/tests/test_gui_headless.py: 14 warnings
src/tests/test_gui_sync.py: 4 warnings
  <string>:31: DeprecationWarning: Pack.padding_top is deprecated. Use Pack.margin_top instead.

src/tests/test_gui_headless.py: 13 warnings
src/tests/test_gui_sync.py: 2 warnings
  <string>:30: DeprecationWarning: Pack.padding is deprecated. Use Pack.margin instead.

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
================= 653 passed, 8 skipped, 64 warnings in 45.30s =================
```
