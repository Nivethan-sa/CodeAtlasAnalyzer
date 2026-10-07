// Builds a nested parent -> child directory/file tree (plus counts) from
// the flat list of relative file paths the scanner already walked.
// This is pure local computation (no GitHub API calls) - it just
// reshapes data we already have into something the frontend can render
// as an actual folder tree instead of a flat file list.

/**
 * @param {string[]} relativeFilePaths e.g. ["backend/server.js", "README.md"]
 * @returns {{ tree: object, total_files: number, total_folders: number, max_depth: number }}
 */
function buildRepoTree(relativeFilePaths) {
  const root = { name: ".", type: "folder", path: "", children: {}, file_count: 0 };
  let maxDepth = 0;

  for (const rawPath of relativeFilePaths || []) {
    if (!rawPath) continue;
    const parts = rawPath.split("/").filter(Boolean);
    if (parts.length === 0) continue;
    maxDepth = Math.max(maxDepth, parts.length);

    let node = root;
    let currentPath = "";
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isFile = i === parts.length - 1;
      currentPath = currentPath ? `${currentPath}/${part}` : part;

      if (isFile) {
        node.children[part] = { name: part, type: "file", path: currentPath };
      } else {
        if (!node.children[part] || node.children[part].type !== "folder") {
          node.children[part] = {
            name: part,
            type: "folder",
            path: currentPath,
            children: {},
            file_count: 0,
          };
        }
        node = node.children[part];
      }
    }
  }

  // Convert the {name: node} maps into sorted arrays (folders first, then
  // files, alphabetically within each group) and roll up file counts so
  // every folder node knows how many files live anywhere underneath it.
  let totalFolders = 0;
  function finalize(node) {
    const childArray = Object.values(node.children).sort((a, b) => {
      if (a.type !== b.type) return a.type === "folder" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    let fileCount = 0;
    const finalizedChildren = childArray.map((child) => {
      if (child.type === "folder") {
        totalFolders++;
        const finalized = finalize(child);
        fileCount += finalized.file_count;
        return finalized;
      }
      fileCount += 1;
      return child;
    });

    return { ...node, children: finalizedChildren, file_count: fileCount };
  }

  const finalizedRoot = finalize(root);

  return {
    tree: finalizedRoot,
    total_files: finalizedRoot.file_count,
    total_folders: totalFolders,
    max_depth: maxDepth,
  };
}

module.exports = buildRepoTree;
