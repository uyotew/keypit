const std = @import("std");
const Aegis256 = std.crypto.aead.aegis.Aegis256;
const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const fatal = std.process.fatal;

const usage =
    \\keypit [--stdout] [-d database_file] [-p password] subcommand
    \\
    \\  --stdout       write the value of the chosen field to stdout,
    \\                 otherwise paste it to the clipboard with wl-copy
    \\                 (only affects 'get' subcommand)
    \\  -d filepath    path to database file, defaults to $XDG_DATA_HOME/keypit.db
    \\  -p password    password used to decrypt and/or encrypt the database file,
    \\                 you will be prompted if -p is not provided
    \\  -h --help      show this
    \\
    \\ subcommands:
    \\  get name [fieldname]
    \\
    \\     if the entry only has one secret field, 
    \\     it's value will be retrieved by default.
    \\     and the clipboard will be cleared after one paste.
    \\
    \\  show [name] 
    \\
    \\     show every entry-name in the database.
    \\     if name is provided, show the contents of that entry 
    \\ 
    \\  modify name [fieldname=value ...] 
    \\  new name [fieldname=value ...]
    \\
    \\     modify or create entries. if value is empty, the field is removed.
    \\     if ? comes after =, as in field=?value, the field's value will be secret.
    \\     if no value is provided after ?, the secret defaults to a random
    \\     64 byte long string of printable characters
    \\
    \\     if you wish to generate the secret differently, you can use
    \\     for example: fieldname=??a30
    \\     where you add an extra ?, and 'a' means alphanumeric,
    \\     and the number is the length of the generated string.
    \\     use 'p' instead of 'a' for all printable characters.
    \\
    \\  copy name new-name
    \\  rename name new-name
    \\
    \\     copy will create a new entry, with a new creation timestamp
    \\     rename will only change the entry's name
    \\
    \\  remove name
    \\
    \\     removes the entire entry
    \\
;

pub fn main() !void {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    const args = try std.process.argsAlloc(arena);

    var use_clipboard = true;
    var filepath_opt: ?[]const u8 = null;
    var password: ?[]const u8 = null;
    var subcommand_opt: ?enum { get, show, modify, new, copy, rename, remove } = null;
    var pairs: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    var entry_name: ?[]const u8 = null;
    // field name for get, and new name for copy and rename
    var field_name_or_new_name: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (subcommand_opt != null and entry_name == null) {
            entry_name = args[i];
        } else if (subcommand_opt) |sub| {
            switch (sub) {
                .get, .copy, .rename => {
                    if (field_name_or_new_name != null) fatal("unexpected argument '{s}'", .{args[i]});
                    field_name_or_new_name = args[i];
                },
                .modify, .new => if (std.mem.indexOfScalar(u8, args[i], '=')) |eq_i| {
                    const gop = try pairs.getOrPut(arena, args[i][0..eq_i]);
                    if (gop.found_existing) fatal("field '{s}' appears more than once", .{gop.key_ptr.*});
                    gop.value_ptr.* = args[i][eq_i + 1 ..];
                } else fatal("unexpected argument '{s}'", .{args[i]}),
                .remove, .show => fatal("unexpected argument '{s}'", .{args[i]}),
            }
        } else if (std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "--help")) {
            std.log.info("{s}", .{usage});
            std.process.exit(0);
        } else if (std.mem.eql(u8, args[i], "--stdout")) {
            use_clipboard = false;
        } else if (std.mem.eql(u8, args[i], "-d")) {
            i += 1;
            if (i >= args.len) fatal("expected filepath after -d", .{});
            filepath_opt = args[i];
        } else if (std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i >= args.len) fatal("expected password after -p", .{});
            password = args[i];
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "get")) {
            subcommand_opt = .get;
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "show")) {
            subcommand_opt = .show;
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "modify")) {
            subcommand_opt = .modify;
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "new")) {
            subcommand_opt = .new;
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "copy")) {
            subcommand_opt = .copy;
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "rename")) {
            subcommand_opt = .rename;
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "remove")) {
            subcommand_opt = .remove;
        } else fatal("unrecognized subcommand '{s}'", .{args[i]});
    }

    const subcommand = subcommand_opt orelse fatal("expected subcommand", .{});
    switch (subcommand) {
        .show => {},
        .modify, .new, .get, .copy, .rename, .remove => {
            if (entry_name == null) fatal("subcommand '{s}' expects an entry name", .{@tagName(subcommand)});
        },
    }

    const filepath = if (filepath_opt) |f| f else blk: {
        const xdg_data_home = std.posix.getenv("XDG_DATA_HOME") orelse fatal("XDG_DATA_HOME is undefined", .{});
        break :blk try std.fs.path.join(arena, &.{ xdg_data_home, "keypit.db" });
    };

    // the file is always only read, and replaced with an atomic file.
    // this is only checked so that modifying operations on read only files
    // error out early (skips password prompt), and
    // arent replaced with a new file if something is modified.
    const open_mode: std.fs.File.OpenMode = switch (subcommand) {
        .modify, .new, .copy, .rename, .remove => .read_write,
        .show, .get => .read_only,
    };

    const file = std.fs.cwd().openFile(filepath, .{ .mode = open_mode }) catch |err| switch (err) {
        error.FileNotFound => switch (subcommand) {
            .show, .get, .modify, .copy, .rename, .remove => {
                fatal("subcommand '{s}' is useless on nonexistent file: {s}", .{ @tagName(subcommand), filepath });
            },
            .new => null,
        },
        else => return err,
    };

    var key: [32]u8 = undefined;
    Sha3_256.hash(password orelse try promptForPassword(arena), &key, .{});

    var database: Database = if (file) |f| try .readFile(arena, f, key) else .{};
    if (file) |f| f.close();

    const stdout = std.io.getStdOut().writer();

    switch (subcommand) {
        .show => {
            if (entry_name) |name| {
                const entry = database.entries.get(name) orelse fatal("entry '{s}' not found", .{name});
                try stdout.print("{s}\n{}\n", .{ name, entry });
            } else {
                for (database.entries.keys(), database.entries.values()) |entry_n, entry| {
                    try stdout.print("{s}\n{}\n", .{ entry_n, entry });
                }
            }
            std.process.exit(0);
        },
        .get => {
            const entry = database.entries.get(entry_name.?) orelse fatal("entry '{s}' not found", .{entry_name.?});
            var value: []const u8 = undefined;

            if (field_name_or_new_name) |field_name| {
                const field = entry.fields.get(field_name) orelse fatal("field '{s}' not found", .{field_name});
                value = field.val;
            } else {
                var secret_fields: u8 = 0;
                for (entry.fields.values()) |field| {
                    if (field.secret) {
                        value = field.val;
                        secret_fields += 1;
                    }
                }
                if (secret_fields == 0) fatal("no secret fields, fieldname need to be provided", .{});
                if (secret_fields > 1) fatal("more than one secret field, fieldname need to be provided", .{});
            }

            if (use_clipboard) {
                var proc = std.process.Child.init(&.{ "wl-copy", "-o", value }, arena);
                _ = proc.spawnAndWait() catch |err| switch (err) {
                    error.FileNotFound => fatal("wl-copy could not be found", .{}),
                    else => return err,
                };
            } else {
                try stdout.print("{s}\n", .{value});
            }
            std.process.exit(0);
        },
        .new => {
            if (database.entries.contains(entry_name.?)) fatal("entry name '{s}' already in use", .{entry_name.?});

            const timestamp = std.time.timestamp();
            var entry: Database.Entry = .{
                .created = timestamp,
                .modified = timestamp,
            };
            for (pairs.keys(), pairs.values()) |field_name, field_raw| {
                if (field_raw.len == 0) fatal("field '{s}' is empty, no empty values allowed", .{field_name});
                try entry.fields.putNoClobber(arena, field_name, try .fromRaw(arena, field_name, field_raw));
            }
            try database.entries.putNoClobber(arena, entry_name.?, entry);
        },
        .modify => {
            const entry = database.entries.getPtr(entry_name.?) orelse fatal("entry '{s}' not found", .{entry_name.?});
            entry.modified = std.time.timestamp();

            for (pairs.keys(), pairs.values()) |field_name, field_raw| {
                if (field_raw.len == 0) {
                    if (!entry.fields.orderedRemove(field_name)) {
                        fatal("cannot remove '{s}', since it doesn't exist", .{field_name});
                    }
                } else {
                    try entry.fields.put(arena, field_name, try .fromRaw(arena, field_name, field_raw));
                }
            }
        },
        .copy => {
            const entry = database.entries.get(entry_name.?) orelse fatal("entry '{s}' not found", .{entry_name.?});
            const new_name = field_name_or_new_name orelse fatal("expected new name after '{s}'", .{entry_name.?});
            if (database.entries.contains(new_name)) fatal("entry name '{s}' already in use", .{new_name});

            const timestamp = std.time.timestamp();
            try database.entries.putNoClobber(arena, new_name, .{
                .created = timestamp,
                .modified = timestamp,
                .fields = entry.fields,
            });
        },
        .rename => {
            const index = database.entries.getIndex(entry_name.?) orelse fatal("entry '{s}' not found", .{entry_name.?});
            const new_name = field_name_or_new_name orelse fatal("expected new name after '{s}'", .{entry_name.?});
            if (database.entries.contains(new_name)) fatal("entry name '{s}' already in use", .{new_name});

            database.entries.values()[index].modified = std.time.timestamp();
            try database.entries.setKey(arena, index, new_name);
        },
        .remove => if (!database.entries.orderedRemove(entry_name.?)) {
            fatal("entry '{s}' not found", .{entry_name.?});
        },
    }

    var atomic_file = try std.fs.cwd().atomicFile(filepath, .{});
    defer atomic_file.deinit();
    try database.write(arena, key, atomic_file.file.writer());
    try atomic_file.finish();
}

////// KEYPIT FORMAT /////
// all in little endian

// unencrypted part:
// first, a u16, version number, which changes when this format changes
// then a 16 byte tag, mac code, to be used in decryption
// the rest is aegis256 encrypted data

// when the encrypted data is decrypted, it's format is as follows
// u16, number of entries,
// for each entry:
// i64, creation timestamp, in seconds, relative to UTC 1970-01-01
// i64, modification timestamp, in seconds, relative to UTC 1970-01-01
// u8, length of unique name
// unique name bytes
// u8, number of fields in entry,
// for each field:
// u8, if 1, then the field is 'secret', other attributes might be added later?
// u8, length of field name
// field name bytes
// u16, length of field value
// field value bytes

const Database = struct {
    entries: std.StringArrayHashMapUnmanaged(Entry) = .empty,
    tag: ?[16]u8 = null,

    const version: u16 = 0;

    const ad = [_]u8{};
    const nonce = [_]u8{0xfa} ** 32;

    comptime {
        std.debug.assert(Aegis256.tag_length == 16);
        std.debug.assert(Aegis256.nonce_length == 32);
    }

    const Entry = struct {
        created: i64,
        modified: i64,
        fields: std.StringArrayHashMapUnmanaged(Field) = .empty,

        const Field = struct {
            secret: bool = false,
            val: []const u8,

            fn fromRaw(arena: std.mem.Allocator, name: []const u8, raw_val: []const u8) !Field {
                var val: []u8 = try arena.dupe(u8, raw_val);
                // default generated value
                if (raw_val.len == 1 and raw_val[0] == '?') {
                    val = try arena.alloc(u8, 64);
                    try generateSecret(val, .printable);
                } else if (raw_val[0] == '?' and raw_val[1] == '?') {
                    if (raw_val.len < 3) fatal("expected either 'a' or 'p' after {s}=??", .{name});
                    if (raw_val.len < 4) fatal("expected a number (length) after {s}={s}", .{ name, raw_val });
                    const len = std.fmt.parseInt(u16, raw_val[3..], 10) catch |err| switch (err) {
                        error.Overflow => fatal("{s}={s} length cannot be bigger than a u16", .{ name, raw_val }),
                        error.InvalidCharacter => fatal("expected a number (length) after {s}={s}", .{ name, raw_val[0..3] }),
                    };
                    if (len == 0) fatal("{s}={s} length cannot be 0", .{ name, raw_val });
                    val = try arena.alloc(u8, len);
                    try generateSecret(val, switch (raw_val[2]) {
                        'a' => .alphanumeric,
                        'p' => .printable,
                        else => fatal("expected either 'a' or 'p' after {s}=??", .{name}),
                    });
                } else if (raw_val[0] == '?') {
                    val = val[1..];
                }
                return .{
                    .secret = raw_val[0] == '?',
                    .val = val,
                };
            }
        };

        pub fn format(entry: Entry, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.writeAll(" created: ");
            try dateFormat(entry.created, writer);
            try writer.writeByte('\n');
            try writer.writeAll(" modified: ");
            try dateFormat(entry.modified, writer);
            try writer.writeByte('\n');

            for (entry.fields.keys(), entry.fields.values()) |field_name, field| {
                try writer.print("  {s}: ", .{field_name});
                if (field.secret) {
                    try writer.writeByteNTimes('*', field.val.len);
                } else {
                    try writer.print("{s}", .{field.val});
                }
                try writer.writeByte('\n');
            }
        }
    };

    pub fn readFile(alc: std.mem.Allocator, file: std.fs.File, key: [32]u8) !Database {
        const reader = file.reader();
        const file_version = try reader.readInt(u16, .little);
        if (file_version != Database.version) {
            fatal("file is version {}, keypit is version {}", .{ file_version, Database.version });
        }
        const tag = try reader.readBytesNoEof(16);
        const ciphertext = try reader.readAllAlloc(alc, 1 << 32);
        defer alc.free(ciphertext);

        const buf = try alc.alloc(u8, ciphertext.len);

        try Aegis256.decrypt(buf, ciphertext, tag, &ad, nonce, key);

        return .{
            .entries = try parseEntries(alc, buf),
            .tag = tag,
        };
    }

    // returned hash map holds references to slices in buf?
    fn parseEntries(alc: std.mem.Allocator, buf: []const u8) !std.StringArrayHashMapUnmanaged(Entry) {
        var i: usize = 0;
        const entries_len = std.mem.readInt(u16, buf[i..][0..2], .little);
        i += 2;
        var entries: std.StringArrayHashMapUnmanaged(Entry) = .empty;
        try entries.ensureUnusedCapacity(alc, entries_len);

        for (0..entries_len) |_| {
            const created = std.mem.readInt(i64, buf[i..][0..8], .little);
            i += 8;
            const modified = std.mem.readInt(i64, buf[i..][0..8], .little);
            i += 8;
            const entry_name_len = buf[i];
            i += 1;
            const entry_name = buf[i..][0..entry_name_len];
            i += entry_name_len;
            const fields_len = buf[i];
            i += 1;
            var fields: std.StringArrayHashMapUnmanaged(Entry.Field) = .empty;
            try fields.ensureUnusedCapacity(alc, fields_len);

            for (0..fields_len) |_| {
                const secret = buf[i] == 1;
                i += 1;
                const name_len = buf[i];
                i += 1;
                const name = buf[i..][0..name_len];
                i += name_len;
                const val_len = std.mem.readInt(u16, buf[i..][0..2], .little);
                i += 2;
                const val = buf[i..][0..val_len];
                i += val_len;

                fields.putAssumeCapacityNoClobber(name, .{
                    .secret = secret,
                    .val = val,
                });
            }
            entries.putAssumeCapacityNoClobber(entry_name, .{
                .created = created,
                .modified = modified,
                .fields = fields,
            });
        }
        return entries;
    }

    pub fn write(db: Database, alc: std.mem.Allocator, key: [32]u8, writer: anytype) !void {
        const buf = try db.serialize(alc);
        defer alc.free(buf);
        const ciphertext = try alc.alloc(u8, buf.len);
        defer alc.free(ciphertext);

        var new_tag: [16]u8 = undefined;
        Aegis256.encrypt(ciphertext, &new_tag, buf, &ad, nonce, key);

        try writer.writeInt(u16, version, .little);
        try writer.writeAll(&new_tag);
        try writer.writeAll(ciphertext);
    }

    fn serialize(db: Database, alc: std.mem.Allocator) ![]const u8 {
        var list = std.ArrayList(u8).init(alc);
        const writer = list.writer();
        if (db.entries.count() > 1 << 16) fatal("more than {} entries in database", .{1 << 16});
        try writer.writeInt(u16, @intCast(db.entries.count()), .little);
        for (db.entries.keys(), db.entries.values()) |entry_name, entry| {
            try writer.writeInt(i64, entry.created, .little);
            try writer.writeInt(i64, entry.modified, .little);
            if (entry_name.len > 1 << 8) fatal("entry '{s}' longer than {}", .{ entry_name, 1 << 8 });
            try writer.writeByte(@intCast(entry_name.len));
            try writer.writeAll(entry_name);
            if (entry.fields.count() > 1 << 8) fatal("more than {} fields in '{s}'", .{ 1 << 8, entry_name });
            try writer.writeByte(@intCast(entry.fields.count()));

            for (entry.fields.keys(), entry.fields.values()) |field_name, field| {
                try writer.writeByte(@intFromBool(field.secret));
                if (field_name.len > 1 << 8) fatal("field name '{s}' longer than {} in entry '{s}'", .{ field_name, 1 << 8, entry_name });
                try writer.writeByte(@intCast(field_name.len));
                try writer.writeAll(field_name);
                if (field.val.len > 1 << 16) fatal("value of field '{s}' in entry '{s}' is longer than {}", .{ field_name, entry_name, 1 << 16 });
                try writer.writeInt(u16, @intCast(field.val.len), .little);
                try writer.writeAll(field.val);
            }
        }
        return list.toOwnedSlice();
    }

    fn dateFormat(stamp_secs: i64, writer: anytype) !void {
        const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(stamp_secs) };
        const day_secs = epoch.getDaySeconds();
        const hour = day_secs.getHoursIntoDay();
        const minute = day_secs.getMinutesIntoHour();
        const secs = day_secs.getSecondsIntoMinute();
        const year_day = epoch.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        try writer.print("{:0>4}-{:0>2}-{:0>2} {:0>2}:{:0>2}:{:0>2} CET", .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            hour,
            minute,
            secs,
        });
    }
};

fn promptForPassword(alc: std.mem.Allocator) ![]const u8 {
    const stdin = std.io.getStdIn();
    if (!stdin.isTty()) return error.NotATty;
    const reader = stdin.reader();
    const writer = std.io.getStdOut().writer();

    try writer.writeAll("Passphrase:");

    const original_termios = std.posix.tcgetattr(stdin.handle) catch unreachable;
    var termios = original_termios;
    termios.lflag.ECHO = false;
    std.posix.tcsetattr(stdin.handle, .FLUSH, termios) catch unreachable;
    defer std.posix.tcsetattr(stdin.handle, .FLUSH, original_termios) catch unreachable;

    var al: std.ArrayList(u8) = .init(alc);
    try reader.streamUntilDelimiter(al.writer(), '\n', 1 << 16);

    // clear line
    try writer.writeAll("\x1b[G\x1b[K");

    return al.toOwnedSlice();
}

fn generateSecret(out: []u8, char_set: enum { printable, alphanumeric }) !void {
    try std.posix.getrandom(out);
    switch (char_set) {
        .alphanumeric => for (out) |*b| {
            b.* >>= 1;
            while (true) switch (b.*) {
                0...47, 58...64, 91...96, 123...127 => {
                    try std.posix.getrandom(b[0..1]);
                    b.* >>= 1;
                },
                else => break,
            };
        },
        .printable => for (out) |*b| {
            b.* >>= 1;
            while (b.* < 33 or b.* > 126) {
                try std.posix.getrandom(b[0..1]);
                b.* >>= 1;
            }
        },
    }
}
