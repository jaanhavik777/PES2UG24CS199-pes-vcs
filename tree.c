// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "index.h"

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_from_index(const Index *index, ObjectID *tree_id_out) {
    if (!index || index->count == 0) {
        return -1;
    }

    Tree tree;
    tree_init(&tree);

    for (size_t i = 0; i < index->count; i++) {
        const IndexEntry *entry = &index->entries[i];
        const char *path = entry->path;

        const char *slash = strchr(path, '/');

        if (!slash) {
            // root file
            tree_add_entry(&tree,
                           path,
                           entry->mode,
                           &entry->hash,
                           OBJ_BLOB);
        } else {
            size_t dir_len = slash - path;

            char dirname[256];
            strncpy(dirname, path, dir_len);
            dirname[dir_len] = '\0';

            // skip duplicate directory processing
            int already_done = 0;
            for (size_t k = 0; k < i; k++) {
                if (strncmp(index->entries[k].path, dirname, dir_len) == 0 &&
                    index->entries[k].path[dir_len] == '/') {
                    already_done = 1;
                    break;
                }
            }
            if (already_done) continue;

            // count entries in this directory
            size_t count = 0;
            for (size_t j = 0; j < index->count; j++) {
                const char *p = index->entries[j].path;
                if (strncmp(p, dirname, dir_len) == 0 &&
                    p[dir_len] == '/') {
                    count++;
                }
            }

            // build subtree index manually (SAFE)
            Index sub_index;
            sub_index.count = 0;

            for (size_t j = 0; j < index->count; j++) {
                const IndexEntry *e = &index->entries[j];

                if (strncmp(e->path, dirname, dir_len) == 0 &&
                    e->path[dir_len] == '/') {

                    IndexEntry *sub = &sub_index.entries[sub_index.count++];

                    sub->mode = e->mode;
                    memcpy(&sub->hash, &e->hash, sizeof(ObjectID));
                    strcpy(sub->path, e->path + dir_len + 1);
                }
            }

            ObjectID subtree_id;
            if (tree_from_index(&sub_index, &subtree_id) != 0) {
                free(sub_index.entries);
                return -1;
            }

            tree_add_entry(&tree,
                           dirname,
                           040000,
                           &subtree_id,
                           OBJ_TREE);
        }
    }

    void *buf = NULL;
    size_t len = 0;

    if (tree_serialize(&tree, &buf, &len) != 0) {
        return -1;
    }

    if (object_write(OBJ_TREE, buf, len, tree_id_out) != 0) {
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}