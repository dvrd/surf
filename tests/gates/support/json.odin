package support

import "core:encoding/json"
import "core:strings"

objects :: proc(text: string) -> (values: [dynamic]json.Value, ok: bool) {
	values = make([dynamic]json.Value)
	rest := text
	for len(rest) > 0 {
		cut := strings.index(rest, "\n")
		line := rest if cut < 0 else rest[:cut]
		if cut < 0 {
			rest = ""
		} else {
			rest = rest[cut + 1:]
		}
		line = strings.trim_space(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		value: json.Value
		if err := json.unmarshal_string(line, &value, .JSON); err != nil {
			release(&values)
			return {}, false
		}
		append(&values, value)
	}
	return values, true
}

only :: proc(text: string) -> (value: json.Value, ok: bool) {
	values, parsed := objects(text)
	if !parsed || len(values) != 1 {
		release(&values)
		return
	}
	value = values[0]
	delete(values)
	return value, true
}

release :: proc(values: ^[dynamic]json.Value) {
	if values == nil {
		return
	}
	for value in values {
		json.destroy_value(value)
	}
	delete(values^)
}

get :: proc(value: json.Value, key: string) -> (json.Value, bool) {
	object, ok := value.(json.Object)
	if !ok {
		return {}, false
	}
	found, exists := object[key]
	return found, exists
}

string_field :: proc(value: json.Value, key: string) -> (string, bool) {
	field, ok := get(value, key)
	if !ok {
		return "", false
	}
	text, is_string := field.(json.String)
	if !is_string {
		return "", false
	}
	return string(text), true
}

bool_field :: proc(value: json.Value, key: string) -> (bool, bool) {
	field, ok := get(value, key)
	if !ok {
		return false, false
	}
	item, is_bool := field.(json.Boolean)
	if !is_bool {
		return false, false
	}
	return bool(item), true
}

is_true :: proc(value: json.Value, key: string) -> bool {
	item, ok := bool_field(value, key)
	return ok && item
}

is_false :: proc(value: json.Value, key: string) -> bool {
	item, ok := bool_field(value, key)
	return ok && !item
}

as_i64 :: proc(value: json.Value) -> (i64, bool) {
	#partial switch n in value {
	case json.Integer:
		return i64(n), true
	case json.Float:
		return i64(n), true
	}
	return 0, false
}

as_f64 :: proc(value: json.Value) -> (f64, bool) {
	#partial switch n in value {
	case json.Integer:
		return f64(n), true
	case json.Float:
		return f64(n), true
	}
	return 0, false
}

i64_field :: proc(value: json.Value, key: string) -> (i64, bool) {
	field, ok := get(value, key)
	if !ok {
		return 0, false
	}
	return as_i64(field)
}

int_field :: proc(value: json.Value, key: string) -> (int, bool) {
	n, ok := i64_field(value, key)
	return int(n), ok
}

f64_field :: proc(value: json.Value, key: string) -> (f64, bool) {
	field, ok := get(value, key)
	if !ok {
		return 0, false
	}
	return as_f64(field)
}

array_field :: proc(value: json.Value, key: string) -> (json.Array, bool) {
	field, ok := get(value, key)
	if !ok {
		return nil, false
	}
	items, is_array := field.(json.Array)
	if !is_array {
		return nil, false
	}
	return items, true
}

eq_string :: proc(value: json.Value, key, want: string) -> bool {
	got, ok := string_field(value, key)
	return ok && got == want
}

eq_int :: proc(value: json.Value, key: string, want: int) -> bool {
	got, ok := int_field(value, key)
	return ok && got == want
}

gt_int :: proc(value: json.Value, key: string, min: int) -> bool {
	got, ok := int_field(value, key)
	return ok && got > min
}

index :: proc(items: json.Array, i: int) -> (json.Value, bool) {
	if i < 0 || i >= len(items) {
		return {}, false
	}
	return items[i], true
}

field_strings :: proc(items: json.Array, key: string, want: []string) -> bool {
	if len(items) != len(want) {
		return false
	}
	for item, i in items {
		got, ok := string_field(item, key)
		if !ok || got != want[i] {
			return false
		}
	}
	return true
}

strings_equal :: proc(items: json.Array, want: []string) -> bool {
	if len(items) != len(want) {
		return false
	}
	for item, i in items {
		text, ok := item.(json.String)
		if !ok || string(text) != want[i] {
			return false
		}
	}
	return true
}

same_strings :: proc(items: json.Array, want: []string) -> bool {
	if len(items) != len(want) {
		return false
	}
	for want_item in want {
		found := false
		for item in items {
			text, ok := item.(json.String)
			if ok && string(text) == want_item {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

empty_or_null :: proc(value: json.Value, key: string) -> bool {
	field, ok := get(value, key)
	if !ok {
		return false
	}
	if _, is_null := field.(json.Null); is_null {
		return true
	}
	items, is_array := field.(json.Array)
	return is_array && len(items) == 0
}

find_event :: proc(values: []json.Value, name: string) -> (json.Value, bool) {
	found: json.Value
	count := 0
	for value in values {
		event, ok := string_field(value, "event")
		if !ok || event != name {
			continue
		}
		found = value
		count += 1
	}
	if count != 1 {
		return {}, false
	}
	return found, true
}
