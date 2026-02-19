schema_version = 2

project {
  license          = "BUSL-1.1"
  copyright_holder = "IBM Corp."

  # (OPTIONAL) A list of globs that should not have copyright or license headers.
  # Supports doublestar glob patterns for more flexibility in defining which
  # files or folders should be ignored
  # Default: []
  header_ignore = [
    ".idea/**",
    "build/**",
    "scratch/**",
    "dist/**",
    "bin/**",
    # "vendor/**",
    # "**autogen**",
  ]
}
