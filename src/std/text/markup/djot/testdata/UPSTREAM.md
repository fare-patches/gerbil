# Djot test fixtures

The 25 `.test` files are unchanged copies from [djot.js 0.3.2, commit d93aff39561a4306c8d59cebd9e07cc6712e1be3](https://github.com/jgm/djot.js/tree/d93aff39561a4306c8d59cebd9e07cc6712e1be3/test). Selection and fence syntax follow `src/functional.spec.ts`, which excludes `filters.test`. The upstream MIT notice is in [LICENSE](LICENSE); it also covers the parser and renderer code adapted from that release.

`conformance-test.ss` runs 296 HTML cases and six syntax-tree cases. The latter compare semantic projections; the position case converts inclusive upstream offsets to half-open ranges. That input is ASCII, so UTF-16 and Gerbil character offsets coincide.

The only HTML expectation adjustment removes the slash before `>` from checkbox elements in `task_lists.test` cases starting at lines 1, 17, and 38. The HTML writer uses HTML void-element syntax. Fixture files are not altered.

## Running the tests

From a built checkout:

```shell
./build.sh test std/text/markup/djot-test.ss std/text/markup/djot/conformance-test.ss
```

`dev-check.ss` checks repeatable rendering, unchanged trees, and identical output with source locations enabled or disabled. Its bounded stress inputs derive from upstream `src/pathological.spec.ts` under the same MIT license. Run it from the checkout root with the current modules on the loadpath:

```shell
gxi -e '(import "src/std/text/markup/djot/dev-check.ss")' \
  -e '(displayln (check-djot-corpus))' \
  -e '(displayln (check-djot-scaling))'
```

## Inventory

25 files, 38,693 bytes. AST denotes an abstract syntax tree.

| File | Bytes | HTML | AST | AST+positions | SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| attributes.test | 5763 | 43 | 2 | 0 | 38d850b195171c9b5cc8c2cb84daed6a923a81904cfc1f6b44090e79cecc4ce7 |
| block_quote.test | 1286 | 15 | 0 | 0 | 91c4d0d80e59f8e2f84c54a614f1aea6784f6d9f62429c09017b68d939da059d |
| code_blocks.test | 592 | 7 | 0 | 0 | 886597279f810dd43b7c6b52c74d6580d217bb64cf371d0a0957023c7945bddf |
| definition_lists.test | 1215 | 6 | 0 | 0 | aa0c74176139b0225ca3bf1d75f2d9224438a652b6b6d4c271c4d53a6a5c0518 |
| symb.test | 179 | 0 | 2 | 0 | 674e7e8c2d5d970dd02ddbb9e3ec216ffc1f323b151d2cce869a141a8c560801 |
| emphasis.test | 2582 | 35 | 0 | 0 | c96e5063241b97010f72cd6230741d1efa998449149be0ad46e793baa54c7337 |
| escapes.test | 662 | 7 | 0 | 0 | 3cad831337b8d48057208f46bd3999f3b1b3b2712387e1dbbc9fc59572e393db |
| fenced_divs.test | 1957 | 9 | 0 | 0 | 7f7af5b8347452b76084ae5db04463e30d5b1227092b4fb38c4b0b5d3b96f4eb |
| footnotes.test | 2925 | 7 | 0 | 0 | 4933d496b23c2fd4f9850dc1f173df0a1237061aad70c2091c3b2d4c1b31ab00 |
| headings.test | 2486 | 18 | 0 | 0 | df5ed1c30e3a83d5dd38e6b49652a53c0a7188d321023aaa8a212a6b7ab75f2c |
| insert_delete_mark.test | 458 | 4 | 0 | 0 | 21288bcbe8e73a03b2c74873e3fe1afc8b8cdb9ed8738eadfae7e832dd37411d |
| links_and_images.test | 4422 | 36 | 0 | 0 | 98baab697a61596354bbcc7d33c123870d98f60d4db7f8d4420159b9d9b379a1 |
| lists.test | 3603 | 33 | 0 | 0 | e8469ad4916421be8b5abb07a8dbcdf8dc209d5d70b51fc9074544dd686b07cc |
| math.test | 921 | 8 | 0 | 0 | 1a3e82ba77fd23f981ec75513244d1b570ba3b4f4fea7290bdffa4f3df3bed14 |
| para.test | 248 | 2 | 0 | 0 | f7ef76e30441c31055bcf4ae532b9710870ee71d042d5a00459c2532a959f67b |
| raw.test | 391 | 4 | 0 | 0 | 89fe38d851da761bf8be5b5681cae2989a16d091e4dc3d613da639e57dedeef0 |
| regression.test | 509 | 5 | 1 | 0 | 44c76d4f965edc470b0cce59a7c1274ea86fb6054bd9aca06d2b880392df7a19 |
| smart.test | 3738 | 21 | 0 | 0 | 715d2ddf42e0f626c96cb50f63a5c1bc6c1e6ea63b787cda6b606a3a9d67862c |
| spans.test | 472 | 6 | 0 | 0 | 6ab550be26c26c282d9804712ed70a06c06fa75a06052c49a759cc9b847ee0e9 |
| sourcepos.test | 252 | 0 | 0 | 1 | 3064aa7ec518252eb587ca94b2c9ed836707e58be5cfc83c09e7491aecd11f1d |
| super_subscript.test | 232 | 4 | 0 | 0 | 162b1d2d4da245859421620cf04406713c798d209bebe7058f66121e911057e7 |
| tables.test | 1922 | 11 | 0 | 0 | c2b3f55dd566dc4e3145f7f5dc34364356e069faeb541a94b28cc4a0f8c94322 |
| task_lists.test | 908 | 3 | 0 | 0 | a22fa5c58ec8ba455f4df9f3c40848cd97bd051b85e2d76b60e2896e9fa591d7 |
| thematic_breaks.test | 286 | 4 | 0 | 0 | e72c5a012847925d108a7dbfc71149c14f43e5a84b1f7383788ca490bb92c058 |
| verbatim.test | 684 | 8 | 0 | 0 | 08b11696a2f0c3a25a74adfa0cbd839f0124a018d501e0ce84d79592803fded2 |
