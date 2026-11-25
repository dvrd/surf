# Agent notes

Surf is an Odin HTTP client. Match the code around the line you are editing. Use tabs. Put one statement on a line. Write a comment only for a constraint the next line does not show.

## Blank lines

Leave at least one blank line between a closing brace and the next statement. This applies to the closing brace of a struct, a procedure, a `switch`, a `for`, and an `if`.

Do not insert that blank line before `else` or `else if`. Those clauses belong to the same `if`. The blank line comes after the whole chain. Do not insert a blank line between the arms of a `switch`. The blank line comes after the `switch` closes.

The only exception is a disposal `defer` tied to an allocation. The assignment comes first. The `if` checks that the allocation produced memory. The `defer` that frees it is the next line, with no blank line in between. The `defer` stays attached because it must run only after that check has succeeded.

```odin
aggregate: Http3_Body

if e := http3_body_init(&aggregate, config, allocator); e.kind != .None {
	return {}, e
}
defer delete(aggregate.body)

sink := http3.Body_Sink {
	data  = &aggregate,
	write = http3_body_write,
}
```

Any statement after that `defer` follows the normal rule. Do not reformat a procedure you are not already changing.

## Imports

Write an import with no name when that name would only repeat the last element of the path. Odin already binds the package to that element.

```odin
import "core:path"
```

`import path "core:path"` states the same name twice. The last element of `core:path` is `path`, and the last element of `shared:async/compress/step` is `step`.

A name belongs on the import when it differs from that last element. Two packages would otherwise share one name, or the call sites already use another name:

```odin
import deflate "shared:async/compress/step"
```

When you change an import, drop a name that matches its path. Leave every other import in the file as it is.
