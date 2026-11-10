import { assert, test } from 'vitest';

import type {
	PackageManager,
	PipelineResource,
	PipelineStep,
	ScriptCommands,
	ServiceManager,
	TargetInput
} from '#lib/schema.ts';

// The authoring types refuse what the engine parses but never runs. These cases
// fail the typecheck if a type admits one again; the asserts only keep vitest happy.

test('a pipeline admits no field the structural gate always refuses', () => {
	const step: PipelineStep = { id: 'a', run: 'true' };
	const pipeline: PipelineResource = { steps: [step], max_concurrency: 1 };
	// @ts-expect-error a step `cwd` is refused: inline a `cd` into `run`
	const with_cwd: PipelineStep = { id: 'a', run: 'true', cwd: '/srv' };
	// @ts-expect-error a step `env` is refused: inline the vars into `run`
	const with_env: PipelineStep = { id: 'a', run: 'true', env: { A: '1' } };
	// @ts-expect-error a step `depends_on` is refused: steps run in declared order
	const with_deps: PipelineStep = { id: 'a', run: 'true', depends_on: ['b'] };
	// @ts-expect-error a pipeline `env` is refused
	const with_shared_env: PipelineResource = { steps: [], env: { A: '1' } };
	// @ts-expect-error a `max_concurrency` above 1 is refused
	const concurrent: PipelineResource = { steps: [], max_concurrency: 2 };
	assert.ok([step, pipeline, with_cwd, with_env, with_deps, with_shared_env, concurrent]);
});

test('a target names only the managers with a backend', () => {
	const managers: Array<PackageManager> = ['apt', 'apk'];
	const services: Array<ServiceManager> = ['systemd', 'openrc'];
	const target: TargetInput = { local: true, package_manager: 'apk', service_manager: 'openrc' };
	// @ts-expect-error `pacman` parses but has no backend
	const pacman: PackageManager = 'pacman';
	// @ts-expect-error `brew` parses but has no backend
	const brew: PackageManager = 'brew';
	// @ts-expect-error `launchd` parses but has no backend
	const launchd: ServiceManager = 'launchd';
	assert.ok([managers, services, target, pacman, brew, launchd]);
});

test('ScriptCommands is the check and run of a script', () => {
	const commands: ScriptCommands = { check: 'true', run: 'true' };
	// @ts-expect-error a script's other fields are not its commands
	const with_cwd: ScriptCommands = { check: 'true', run: 'true', cwd: '/' };
	assert.deepEqual(Object.keys(commands), ['check', 'run']);
	assert.ok(with_cwd);
});
