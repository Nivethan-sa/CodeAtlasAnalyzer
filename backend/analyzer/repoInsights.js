const axios = require("axios");

const GITHUB_API = "https://api.github.com";

/** Pulls the page number out of the `rel="last"` entry of a GitHub
 * pagination Link header, e.g. `<...?page=42>; rel="last"`. Used to get
 * an exact total count (commits, branches, PRs) from a single request
 * with per_page=1, instead of paging through everything by hand. */
function lastPageFromLinkHeader(linkHeader) {
  if (!linkHeader) return 1;
  const match = linkHeader
    .split(",")
    .map((part) => part.trim())
    .find((part) => part.endsWith('rel="last"'));
  if (!match) return 1;
  const pageMatch = match.match(/[?&]page=(\d+)/);
  return pageMatch ? parseInt(pageMatch[1], 10) : 1;
}

async function getBranches(owner, repo, headers) {
  try {
    const res = await axios.get(
      `${GITHUB_API}/repos/${owner}/${repo}/branches`,
      {
        headers,
        params: { per_page: 100 },
      },
    );
    const totalBranches =
      lastPageFromLinkHeader(res.headers?.link) > 1
        ? (lastPageFromLinkHeader(res.headers.link) - 1) * 100 + 1 // lower-bound estimate
        : res.data.length;

    return {
      available: true,
      total_branches: res.data.length < 100 ? res.data.length : totalBranches,
      truncated: res.data.length >= 100,
      branches: res.data.map((b) => ({
        name: b.name,
        commit_sha: b.commit?.sha || null,
        protected: !!b.protected,
      })),
    };
  } catch (error) {
    return {
      available: false,
      reason: error.message,
      branches: [],
      total_branches: 0,
    };
  }
}

async function getCommits(owner, repo, headers, defaultBranch) {
  try {
    const [recentRes, countRes] = await Promise.all([
      axios.get(`${GITHUB_API}/repos/${owner}/${repo}/commits`, {
        headers,
        params: { sha: defaultBranch, per_page: 30 },
      }),
      axios.get(`${GITHUB_API}/repos/${owner}/${repo}/commits`, {
        headers,
        params: { sha: defaultBranch, per_page: 1 },
      }),
    ]);

    const totalCommits = lastPageFromLinkHeader(countRes.headers?.link);

    return {
      available: true,
      total_commits: totalCommits,
      recent: recentRes.data.map((c) => ({
        sha: c.sha?.slice(0, 7),
        message: (c.commit?.message || "").split("\n")[0],
        author: c.commit?.author?.name || c.author?.login || "unknown",
        date: c.commit?.author?.date || null,
        url: c.html_url,
      })),
    };
  } catch (error) {
    return {
      available: false,
      reason: error.message,
      total_commits: 0,
      recent: [],
    };
  }
}

async function getPullRequests(owner, repo, headers) {
  try {
    const res = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}/pulls`, {
      headers,
      params: {
        state: "all",
        per_page: 100,
        sort: "created",
        direction: "desc",
      },
    });

    const pulls = res.data.map((pr) => ({
      number: pr.number,
      title: pr.title,
      state: pr.merged_at ? "merged" : pr.state,
      author: pr.user?.login || "unknown",
      source_branch: pr.head?.ref || null,
      target_branch: pr.base?.ref || null,
      created_at: pr.created_at,
      merged_at: pr.merged_at,
      closed_at: pr.closed_at,
      url: pr.html_url,
    }));

    const counts = pulls.reduce(
      (acc, pr) => {
        acc[pr.state] = (acc[pr.state] || 0) + 1;
        return acc;
      },
      { open: 0, closed: 0, merged: 0 },
    );

    return {
      available: true,
      truncated: res.data.length >= 100,
      counts,
      pull_requests: pulls,
    };
  } catch (error) {
    return {
      available: false,
      reason: error.message,
      counts: { open: 0, closed: 0, merged: 0 },
      pull_requests: [],
    };
  }
}

function buildMetadata(repoApiData) {
  if (!repoApiData) return { available: false };
  return {
    available: true,
    full_name: repoApiData.full_name,
    default_branch: repoApiData.default_branch,
    stars: repoApiData.stargazers_count,
    forks: repoApiData.forks_count,
    watchers: repoApiData.subscribers_count ?? repoApiData.watchers_count,
    open_issues: repoApiData.open_issues_count,
    size_kb: repoApiData.size,
    license: repoApiData.license?.spdx_id || repoApiData.license?.name || null,
    topics: repoApiData.topics || [],
    is_fork: !!repoApiData.fork,
    is_archived: !!repoApiData.archived,
    created_at: repoApiData.created_at,
    updated_at: repoApiData.updated_at,
    pushed_at: repoApiData.pushed_at,
  };
}

function buildBranchHierarchy(
  branchesResult,
  pullRequestsResult,
  defaultBranch,
) {
  const branchList = branchesResult?.branches || [];
  if (!branchesResult?.available || branchList.length === 0) {
    return {
      available: false,
      root: defaultBranch || null,
      tree: [],
      max_depth: 0,
    };
  }

  const branchNames = new Set(branchList.map((b) => b.name));
  const nodesByName = new Map(
    branchList.map((b) => [
      b.name,
      {
        name: b.name,
        protected: !!b.protected,
        commit_sha: b.commit_sha,
        is_default: b.name === defaultBranch,
        children: [],
      },
    ]),
  );

  // source_branch -> target_branch, one entry per branch. PRs come back
  // sorted newest-first (see getPullRequests), so keeping only the first
  // match per source branch prefers its most recent PR.
  const parentOf = new Map();
  for (const pr of pullRequestsResult?.pull_requests || []) {
    const src = pr.source_branch;
    const tgt = pr.target_branch;
    if (!src || !tgt || src === tgt) continue;
    if (src === defaultBranch) continue; // root can't be its own child
    if (!branchNames.has(src) || !branchNames.has(tgt)) continue;
    if (!parentOf.has(src)) parentOf.set(src, tgt);
  }

  // Guards against a PR chain looping back on itself (rare, but two open
  // PRs cross-targeting each other would otherwise infinite-loop below).
  function eventuallyReachesRoot(name) {
    const seen = new Set();
    let current = name;
    while (parentOf.has(current)) {
      if (seen.has(current)) return false;
      seen.add(current);
      current = parentOf.get(current);
    }
    return true;
  }

  const hasRoot = defaultBranch && branchNames.has(defaultBranch);
  for (const name of branchNames) {
    if (name === defaultBranch) continue;
    if (!parentOf.has(name)) {
      if (hasRoot) parentOf.set(name, defaultBranch);
    } else if (!eventuallyReachesRoot(name)) {
      if (hasRoot) parentOf.set(name, defaultBranch);
      else parentOf.delete(name);
    }
  }

  const roots = [];
  for (const [name, node] of nodesByName) {
    if (name === defaultBranch) {
      roots.push(node);
      continue;
    }
    const parentName = parentOf.get(name);
    if (parentName && parentName !== name && nodesByName.has(parentName)) {
      node.parent = parentName;
      nodesByName.get(parentName).children.push(node);
    } else {
      node.parent = null;
      roots.push(node); // no default branch to hang off, or unresolved
    }
  }

  function sortTree(nodes) {
    nodes.sort((a, b) => {
      if (a.is_default !== b.is_default) return a.is_default ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    nodes.forEach((n) => sortTree(n.children));
  }
  sortTree(roots);

  let maxDepth = 0;
  function computeDepth(node, depth) {
    maxDepth = Math.max(maxDepth, depth);
    node.children.forEach((c) => computeDepth(c, depth + 1));
  }
  roots.forEach((r) => computeDepth(r, 0));

  return {
    available: true,
    root: defaultBranch || null,
    tree: roots,
    max_depth: maxDepth,
    inferred_from: "pull_request_base_head",
  };
}

/**
 * Best-effort ownership/bus-factor insights, built from GitHub's API since
 * the local clone is `--depth 1` (single commit, no history to mine
 * locally - see server.js's `git clone --depth 1`).
 *
 * Two independent, separately-degrading pieces:
 *   1. Top contributors overall - a single request to GitHub's
 *      `stats/contributors` endpoint, which already aggregates the whole
 *      repo's history server-side (no need to page through commits
 *      ourselves for this part). GitHub sometimes answers 202 with an
 *      empty body while it computes these stats for a repo it hasn't
 *      cached yet - that's not a failure, just "not ready this time"; this
 *      section simply won't be available for that particular scan rather
 *      than blocking on/retrying a background job.
 *   2. A "bus factor" sample - which top-level directories were touched by
 *      only one author, across a small, capped, concurrently-fetched set
 *      of the most recent commits (reusing the same `recent commits`
 *      already returned by getCommits(), not a separate history walk).
 *      GitHub's commit *list* endpoint doesn't include changed files (only
 *      the single-commit endpoint does), so this is unavoidably one
 *      request per sampled commit - kept small (capped at
 *      BUS_FACTOR_SAMPLE_SIZE) and run concurrently via Promise.allSettled
 *      so one bad commit lookup can't sink the rest. This is a *sample*,
 *      not full-history bus factor, and is labelled as such wherever it's
 *      shown.
 */
const BUS_FACTOR_SAMPLE_SIZE = 20;

async function getContributorInsights(owner, repo, headers, recentCommits = []) {
  let topContributors = [];
  let contributorsAvailable = false;
  try {
    const res = await axios.get(
      `${GITHUB_API}/repos/${owner}/${repo}/stats/contributors`,
      { headers },
    );
    if (Array.isArray(res.data) && res.data.length > 0) {
      contributorsAvailable = true;
      topContributors = res.data
        .map((c) => ({ login: c.author?.login || "unknown", commits: c.total || 0 }))
        .filter((c) => c.commits > 0)
        .sort((a, b) => b.commits - a.commits)
        .slice(0, 10);
    }
  } catch (error) {
    contributorsAvailable = false;
  }

  const sample = recentCommits.slice(0, BUS_FACTOR_SAMPLE_SIZE);
  const dirAuthors = new Map(); // top-level path -> Set(author names)
  let busFactorAvailable = false;

  if (sample.length > 0) {
    const details = await Promise.allSettled(
      sample.map((c) =>
        axios.get(`${GITHUB_API}/repos/${owner}/${repo}/commits/${c.sha}`, { headers }),
      ),
    );
    for (const result of details) {
      if (result.status !== "fulfilled") continue;
      const data = result.value.data;
      const files = data.files || [];
      if (files.length === 0) continue;
      busFactorAvailable = true;
      const author = data.commit?.author?.name || data.author?.login || "unknown";
      for (const f of files) {
        if (!f.filename) continue;
        const topLevel = f.filename.includes("/") ? f.filename.split("/")[0] : f.filename;
        if (!dirAuthors.has(topLevel)) dirAuthors.set(topLevel, new Set());
        dirAuthors.get(topLevel).add(author);
      }
    }
  }

  const busFactorRisks = [...dirAuthors.entries()]
    .filter(([, authors]) => authors.size === 1)
    .map(([path, authors]) => ({ path, sole_contributor: [...authors][0] }))
    .sort((a, b) => a.path.localeCompare(b.path))
    .slice(0, 15);

  return {
    available: contributorsAvailable || busFactorAvailable,
    top_contributors: topContributors,
    contributors_available: contributorsAvailable,
    bus_factor_available: busFactorAvailable,
    bus_factor_sample_size: sample.length,
    bus_factor_risks: busFactorRisks,
  };
}

/** Fetches branches, commits and pull requests concurrently and bundles
 * them with the metadata block. Never throws - each section degrades to
 * `available: false` independently on failure (rate limit, network, etc). */
async function getRepoInsights({
  owner,
  repo,
  headers,
  defaultBranch,
  repoApiData,
}) {
  const [branches, commits, pullRequests] = await Promise.all([
    getBranches(owner, repo, headers),
    getCommits(owner, repo, headers, defaultBranch),
    getPullRequests(owner, repo, headers),
  ]);

  const branchHierarchy = buildBranchHierarchy(
    branches,
    pullRequests,
    defaultBranch,
  );

  // Ownership insights reuse the commits already fetched above rather
  // than fetching their own separate commit list - degrades to
  // `available: false` on its own if GitHub's commit data isn't available
  // (no token, rate-limited, etc.), same as every other section here.
  const contributors = await getContributorInsights(
    owner,
    repo,
    headers,
    commits.recent || [],
  );

  return {
    metadata: buildMetadata(repoApiData),
    branches,
    commits,
    pull_requests: pullRequests,
    branch_hierarchy: branchHierarchy,
    contributors,
  };
}

module.exports = {
  getRepoInsights,
  getBranches,
  getCommits,
  getPullRequests,
  getContributorInsights,
  buildMetadata,
  buildBranchHierarchy,
};
