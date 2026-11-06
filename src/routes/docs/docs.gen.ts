import type { Gen } from '@fuzdev/gro/gen.ts';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';
import { mdz_parse, type MdzNode, type MdzNodeLink } from '@fuzdev/mdz/mdz.ts';

/**
 * Renders every `docs/*.md` at the repo root as a tome at `/docs/<slug>`.
 *
 * `docs/*.md` is the single source of truth — GitHub renders the files, and this
 * generator emits one route per doc whose static content `svelte_preprocess_mdz`
 * precompiles at build time, plus the `docs.ts` tome list `tomes.ts` spreads in.
 * Edit `DOCS` below to reorder or recategorize, then run `gro gen`.
 *
 * @module
 */

export type DocCategory = 'guide' | 'reference' | 'contributing';

export interface DocEntry {
	/** The `docs/<slug>.md` filename stem, also the route segment and tome slug. */
	slug: string;
	category: DocCategory;
}

/**
 * The docs in tome order. A doc on disk but missing here still renders, appended
 * as `reference` with a warning; an entry missing on disk fails gen.
 */
export const DOCS: Array<DocEntry> = [
	{ slug: 'introduction', category: 'guide' },
	{ slug: 'install', category: 'guide' },
	{ slug: 'getting-started', category: 'guide' },
	{ slug: 'concepts', category: 'guide' },
	{ slug: 'configs', category: 'guide' },
	{ slug: 'deploy', category: 'guide' },
	{ slug: 'security', category: 'guide' },
	{ slug: 'comparison', category: 'guide' },
	{ slug: 'faq', category: 'guide' },
	{ slug: 'stability', category: 'guide' },
	{ slug: 'cli', category: 'reference' },
	{ slug: 'resources', category: 'reference' },
	{ slug: 'recipes', category: 'reference' },
	{ slug: 'targets', category: 'reference' },
	{ slug: 'env', category: 'reference' },
	{ slug: 'lock', category: 'reference' },
	{ slug: 'detection', category: 'reference' },
	{ slug: 'glossary', category: 'reference' },
	{ slug: 'contributing', category: 'contributing' },
	{ slug: 'testing', category: 'contributing' },
	{ slug: 'differential', category: 'contributing' }
];

const DOCS_DIR = 'docs';
const ROUTES_DIR = 'src/routes/docs';
const UNLISTED_CATEGORY: DocCategory = 'reference';

const SLUG_RE = /^[a-z0-9][a-z0-9_-]*$/;
const TITLE_RE = /^# +(.+?) *$/m;

// a backtick code span (preserved), a docs-sibling `./foo.md` (optional anchor),
// or a repo-root `../path` reaching outside `docs/`
const LINK_RE =
	/(`[^`\n]*`)|\.\/([\w-]+)\.md(#[\w-]+)?\b|\.\.\/((?:[\w.-]+\/)*[\w.-]*[\w-])(?=[\s)\]#,;:]|$)/g;

interface DocFile {
	slug: string;
	category: DocCategory;
	title: string;
	content: string;
}

const to_github_url = (repository: string, path: string): string =>
	`${repository.replace(/\/$/, '')}/blob/main/${path}`;

const load_repository_url = (): string => {
	const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { repository?: unknown };
	const repo = pkg.repository;
	const url = typeof repo === 'string' ? repo : (repo as { url?: string } | undefined)?.url;
	if (!url) throw Error('package.json `repository` is required to link repo paths from docs');
	return url.replace(/^git\+/, '').replace(/\.git$/, '');
};

/**
 * Rewrites relative links outside fenced code blocks and code spans:
 * `./foo.md#x` → `/docs/foo#x` (a missing doc warns and falls back to its GitHub URL),
 * `../crates/x` → the GitHub URL of `crates/x`.
 */
const rewrite_links = (
	content: string,
	file: string,
	slugs: Set<string>,
	repository: string,
	log: { warn: (...args: Array<unknown>) => void }
): string => {
	const lines = content.split('\n');
	let in_fence = false;
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i]!;
		if (line.trimStart().startsWith('```')) {
			in_fence = !in_fence;
			continue;
		}
		if (in_fence) continue;
		lines[i] = line.replace(
			LINK_RE,
			(
				match,
				code_span: string | undefined,
				doc_slug: string | undefined,
				hash: string | undefined,
				repo_path: string | undefined
			) => {
				if (code_span !== undefined) return code_span;
				if (doc_slug !== undefined) {
					if (!slugs.has(doc_slug)) {
						// a mid-restructure link builds against GitHub instead of a 404 route
						log.warn(
							`docs.gen.ts: ${file}:${i + 1} links missing doc \`${match}\` — using its GitHub URL`
						);
						return to_github_url(repository, `${DOCS_DIR}/${doc_slug}.md${hash ?? ''}`);
					}
					return `/docs/${doc_slug}${hash ?? ''}`;
				}
				if (repo_path !== undefined && !repo_path.startsWith('..')) {
					return to_github_url(repository, repo_path);
				}
				return match;
			}
		);
	}
	return lines.join('\n');
};

const collect_heading_ids = (nodes: Array<MdzNode>, ids: Set<string>): void => {
	for (const node of nodes) {
		if (node.type === 'Heading' && node.id) ids.add(node.id);
		if ('children' in node) collect_heading_ids(node.children, ids);
	}
};

const collect_links = (nodes: Array<MdzNode>, links: Array<MdzNodeLink>): void => {
	for (const node of nodes) {
		if (node.type === 'Link') links.push(node);
		if ('children' in node) collect_links(node.children, links);
	}
};

/** Reads the docs in `DOCS` order, appending unlisted files, failing on missing ones. */
const load_docs = (log: { warn: (...args: Array<unknown>) => void }): Array<DocFile> => {
	const on_disk = readdirSync(DOCS_DIR)
		.filter((f) => f.endsWith('.md'))
		.map((f) => basename(f, '.md'))
		.sort();
	const on_disk_set = new Set(on_disk);

	const seen: Set<string> = new Set();
	const missing: Array<string> = [];
	for (const entry of DOCS) {
		if (seen.has(entry.slug)) throw Error(`docs.gen.ts: duplicate entry \`${entry.slug}\``);
		seen.add(entry.slug);
		if (!on_disk_set.has(entry.slug)) missing.push(entry.slug);
	}
	if (missing.length) {
		throw Error(
			`docs.gen.ts: listed docs missing on disk: ${missing.map((s) => `${DOCS_DIR}/${s}.md`).join(', ')} — remove them from \`DOCS\` or restore the files`
		);
	}

	const entries: Array<DocEntry> = [...DOCS];
	for (const slug of on_disk) {
		if (seen.has(slug)) continue;
		log.warn(
			`docs.gen.ts: \`${DOCS_DIR}/${slug}.md\` is not in \`DOCS\` — appending it as '${UNLISTED_CATEGORY}'`
		);
		entries.push({ slug, category: UNLISTED_CATEGORY });
	}

	return entries.map(({ slug, category }) => {
		if (!SLUG_RE.test(slug)) {
			throw Error(`docs.gen.ts: \`${DOCS_DIR}/${slug}.md\` is not a URL-safe slug`);
		}
		const raw = readFileSync(join(DOCS_DIR, slug + '.md'), 'utf8');
		const match = TITLE_RE.exec(raw);
		if (!match || raw.slice(0, match.index).trim()) {
			throw Error(`docs.gen.ts: \`${DOCS_DIR}/${slug}.md\` must start with a \`# \` title`);
		}
		// the tome header renders the title, so the body drops it
		const content = raw.slice(match.index + match[0].length).replace(/^\n+/, '');
		return { slug, category, title: match[1]!, content };
	});
};

/**
 * Warns for each `#anchor` link that resolves to no mdz heading id, and drops the
 * anchor so the link lands on the doc — SvelteKit's prerender fails on a missing id.
 */
const fix_anchors = (
	docs: Array<DocFile>,
	log: { warn: (...args: Array<unknown>) => void }
): void => {
	const ids_by_slug: Map<string, Set<string>> = new Map();
	const parsed: Map<string, Array<MdzNode>> = new Map();
	for (const doc of docs) {
		const nodes = mdz_parse(doc.content);
		parsed.set(doc.slug, nodes);
		const ids: Set<string> = new Set();
		collect_heading_ids(nodes, ids);
		ids_by_slug.set(doc.slug, ids);
	}
	for (const doc of docs) {
		const links: Array<MdzNodeLink> = [];
		collect_links(parsed.get(doc.slug)!, links);
		// splice back to front so earlier offsets stay valid
		for (const link of links.reverse()) {
			const m = /^(?:\/docs\/([\w-]+))?#(.+)$/.exec(link.reference);
			if (!m) continue;
			const target = m[1] ?? doc.slug;
			if (ids_by_slug.get(target)?.has(m[2]!)) continue;
			log.warn(
				`docs.gen.ts: ${DOCS_DIR}/${doc.slug}.md links \`${link.reference}\` — no such heading id, linking the doc instead`
			);
			const span = doc.content.slice(link.start, link.end);
			const i = span.lastIndexOf(link.reference);
			if (i === -1) continue;
			doc.content =
				doc.content.slice(0, link.start + i) +
				`/docs/${target}` +
				doc.content.slice(link.start + i + link.reference.length);
		}
	}
};

export const gen: Gen = ({ origin_path, log }) => {
	const banner = `// generated by ${origin_path} - do not edit`;
	const svelte_banner = `<!-- generated by ${origin_path} - do not edit -->`;

	const repository = load_repository_url();
	const docs = load_docs(log);
	const slugs = new Set(docs.map((d) => d.slug));
	for (const doc of docs) {
		doc.content = rewrite_links(doc.content, `${DOCS_DIR}/${doc.slug}.md`, slugs, repository, log);
	}
	fix_anchors(docs, log);

	// a removed doc leaves its generated route behind — gen can't delete it, so fail loudly
	for (const dir of readdirSync(ROUTES_DIR, { withFileTypes: true })) {
		if (!dir.isDirectory() || slugs.has(dir.name)) continue;
		const page = join(ROUTES_DIR, dir.name, '+page.svelte');
		if (existsSync(page) && readFileSync(page, 'utf8').startsWith(svelte_banner)) {
			throw Error(`docs.gen.ts: stale generated route \`${page}\` — its doc is gone, delete it`);
		}
	}

	// never overwrite a hand-written route (`api`, `library`) with a doc of the same name
	for (const doc of docs) {
		const page = join(ROUTES_DIR, doc.slug, '+page.svelte');
		if (existsSync(page) && !readFileSync(page, 'utf8').startsWith(svelte_banner)) {
			throw Error(
				`docs.gen.ts: \`${DOCS_DIR}/${doc.slug}.md\` collides with hand-written \`${page}\``
			);
		}
	}

	const pages = docs.map((doc) => ({
		filename: join(doc.slug, '+page.svelte'),
		// `<` escaped so content can't close the script; `content` is a static const
		// so `svelte_preprocess_mdz` precompiles it
		content: `${svelte_banner}

<script lang="ts">
	import Mdz from '@fuzdev/mdz/Mdz.svelte';
	import TomeContent from '@fuzdev/fuz_ui/TomeContent.svelte';
	import {tome_get_by_slug} from '@fuzdev/fuz_ui/tome.ts';

	const tome = tome_get_by_slug(${JSON.stringify(doc.slug)});

	const content = ${JSON.stringify(doc.content).replaceAll('<', '\\u003c')};
</script>

<svelte:head>
	<title>${doc.title.replaceAll('<', '&lt;').replaceAll('{', '&#123;')} — zap</title>
</svelte:head>

<TomeContent {tome}>
	<Mdz {content} />
</TomeContent>
`
	}));

	const imports = docs.map((d, i) => `import Doc${i} from './${d.slug}/+page.svelte';`).join('\n');
	const entries = docs
		.map(
			(d, i) => `	{
		slug: ${JSON.stringify(d.slug)},
		title: ${JSON.stringify(d.title)},
		category: ${JSON.stringify(d.category)},
		Component: Doc${i},
		related_tomes: [],
		related_modules: [],
		related_declarations: []
	}`
		)
		.join(',\n');

	const data = `${banner}

import type {Tome} from '@fuzdev/fuz_ui/tome.ts';
${imports}

/** The \`docs/*.md\` tomes in \`DOCS\` order. */
export const docs_tomes: Array<Tome> = [
${entries}
];
`;

	return [{ filename: 'docs.ts', content: data }, ...pages];
};
