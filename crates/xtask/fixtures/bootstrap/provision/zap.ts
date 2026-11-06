// The bootstrap-replace scenario's first bring-up: run with `--bootstrap`, as `ops`,
// it creates the replacement user with `ops`'s keys and a sudo grant of its own.

import type { ZapBuilder } from '../../../../../src/lib/zap.ts';
import { declare_replacement } from '../common.ts';

export default (zap: ZapBuilder): void => {
	declare_replacement(zap, { copy_from: 'ops' });
};
