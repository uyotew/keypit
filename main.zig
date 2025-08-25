const std = @import("std");
const Aegis256 = std.crypto.aead.aegis.Aegis256;
const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const fatal = std.process.fatal;

var read_buffer: [4096]u8 = undefined;
var write_buffer: [4096]u8 = undefined;

const usage =
    \\usage:
    \\ keypit [--stdout] [-d filepath] [-p password] subcommand
    \\
    \\  --stdout       when using 'get', write field value to stdout,
    \\                 defaults to write to clipboard with wl-copy
    \\  -d filepath    path to database file, defaults to $XDG_DATA_HOME/keypit.db
    \\  -p password    skip prompt, and use password to decrypt the database file
    \\  -h --help      show this help
    \\  -v --version   show keypit file format version
    \\
    \\ subcommands:
    \\  get              entry-name [field-name]
    \\  show             [entry-name]
    \\  modify           entry-name [field-name=value ...]
    \\  new              entry-name [field-name=value ...]
    \\  copy             entry-name new-entry-name
    \\  rename           entry-name new-entry-name
    \\  remove           entry-name
    \\  change-password
    \\
    \\ new and modify: field-name=value
    \\  field-name=         the field is removed
    \\  field-name=?value   value is secret
    \\  field-name=?        generate 64 byte string of printable characters
    \\  field-name=??pN     generate N byte string of printable characters
    \\  field-name=??aN     generate N byte string of alphanumeric characters
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
    var subcommand_opt: ?enum { get, show, modify, new, copy, rename, remove, change_password } = null;
    var pairs: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    var entry_name: ?[]const u8 = null;
    // field name for get, and new name for copy and rename
    var field_name_or_new_name: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (subcommand_opt != null and subcommand_opt != .change_password and entry_name == null) {
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
                .remove, .show, .change_password => fatal("unexpected argument '{s}'", .{args[i]}),
            }
        } else if (std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "--help")) {
            std.log.info("{s}", .{usage});
            std.process.exit(0);
        } else if (std.mem.eql(u8, args[i], "-v") or std.mem.eql(u8, args[i], "--version")) {
            std.log.info("version: {}", .{Database.version});
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
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "change-password")) {
            subcommand_opt = .change_password;
        } else fatal("unrecognized subcommand '{s}'", .{args[i]});
    }

    const subcommand = subcommand_opt orelse fatal("expected subcommand", .{});
    switch (subcommand) {
        .show, .change_password => {},
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
        .modify, .new, .copy, .rename, .remove, .change_password => .read_write,
        .show, .get => .read_only,
    };

    const file = std.fs.cwd().openFile(filepath, .{ .mode = open_mode }) catch |err| switch (err) {
        error.FileNotFound => switch (subcommand) {
            .show, .get, .modify, .copy, .rename, .remove, .change_password => {
                fatal("subcommand '{s}' is useless on nonexistent file: {s}", .{ @tagName(subcommand), filepath });
            },
            .new => null,
        },
        error.AccessDenied => switch (open_mode) {
            .read_write => fatal("write access denied for {s}", .{filepath}),
            .read_only => fatal("read access denied for {s}", .{filepath}),
            else => unreachable,
        },
        else => return err,
    };

    var key: [32]u8 = undefined;
    Sha3_256.hash(password orelse try promptForPassword(arena), &key, .{});

    var database: Database = if (file) |f| try .readFile(arena, f, key) else .{};
    if (file) |f| f.close();

    var stdout_writer = std.fs.File.stdout().writer(&write_buffer);
    const stdout = &stdout_writer.interface;

    switch (subcommand) {
        .show => {
            if (entry_name) |name| {
                const entry = database.entries.get(name) orelse fatal("entry '{s}' not found", .{name});
                try stdout.print("{s}\n{f}\n", .{ name, entry });
            } else {
                for (database.entries.keys(), database.entries.values()) |entry_n, entry| {
                    try stdout.print("{s}\n{f}\n", .{ entry_n, entry });
                }
            }
            try stdout.flush();
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
                var proc = std.process.Child.init(&.{ "wl-copy", value }, arena);
                _ = proc.spawnAndWait() catch |err| switch (err) {
                    error.FileNotFound => fatal("wl-copy could not be found", .{}),
                    else => return err,
                };
                const stdin_file = std.fs.File.stdin();

                const original_termios = std.posix.tcgetattr(stdin_file.handle) catch unreachable;
                var termios = original_termios;
                termios.lflag.ISIG = false;
                termios.lflag.ECHO = false;
                termios.lflag.ICANON = false;
                std.posix.tcsetattr(stdin_file.handle, .FLUSH, termios) catch unreachable;
                defer std.posix.tcsetattr(stdin_file.handle, .FLUSH, original_termios) catch unreachable;

                try stdout.print("press any key to clear clipboard and quit", .{});
                try stdout.flush();
                var stdin_reader = stdin_file.reader(&read_buffer);
                _ = try stdin_reader.interface.takeByte();

                // clear line
                try stdout.writeAll("\x1b[G\x1b[K");

                proc = std.process.Child.init(&.{ "wl-copy", "-c" }, arena);
                _ = proc.spawnAndWait() catch |err| switch (err) {
                    error.FileNotFound => fatal("wl-copy could not be found", .{}),
                    else => return err,
                };
            } else {
                try stdout.print("{s}\n", .{value});
            }
            try stdout.flush();
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
        .change_password => {
            try stdout.writeAll("New ");
            try stdout.flush();
            const new_password = try promptForPassword(arena);
            try stdout.writeAll("Repeat New ");
            try stdout.flush();
            if (!std.mem.eql(u8, new_password, try promptForPassword(arena))) fatal("not the same password", .{});
            Sha3_256.hash(new_password, &key, .{});
        },
    }

    var atomic_file = try std.fs.cwd().atomicFile(filepath, .{ .write_buffer = &write_buffer });
    defer atomic_file.deinit();
    try database.write(&atomic_file.file_writer.interface, arena, key);
    try atomic_file.file_writer.file.sync();
    try atomic_file.finish();
}

////// KEYPIT FORMAT /////
// all in little endian

// unencrypted part:
// first, a u16, version number, which changes when this format changes
// then a 16 byte tag, mac code, to be used in decryption
// then a 32 byte nonce, used in decryption as well
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

    const version: u16 = 1;

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

        pub fn format(entry: Entry, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeAll(" created: ");
            try dateFormat(writer, entry.created);
            try writer.writeByte('\n');
            try writer.writeAll(" modified: ");
            try dateFormat(writer, entry.modified);
            try writer.writeByte('\n');

            for (entry.fields.keys(), entry.fields.values()) |field_name, field| {
                try writer.print("  {s}: ", .{field_name});
                if (field.secret) {
                    try writer.splatByteAll('*', field.val.len);
                } else {
                    try writer.print("{s}", .{field.val});
                }
                try writer.writeByte('\n');
            }
        }

        fn dateFormat(writer: *std.Io.Writer, stamp_secs: i64) !void {
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

    pub fn readFile(alc: std.mem.Allocator, file: std.fs.File, key: [32]u8) !Database {
        var file_reader = file.reader(&read_buffer);
        const r = &file_reader.interface;

        const file_version = try r.takeInt(u16, .little);
        if (file_version > Database.version) {
            fatal("file is version {}, keypit is version {}", .{ file_version, Database.version });
        }
        const tag = (try r.takeArray(16)).*;
        // 0-eth version used a constant nonce
        const nonce = if (file_version == 0) [_]u8{0xfa} ** 32 else (try r.takeArray(32)).*;
        const ciphertext = try r.allocRemaining(alc, .unlimited);
        defer alc.free(ciphertext);

        const buf = try alc.alloc(u8, ciphertext.len);

        Aegis256.decrypt(buf, ciphertext, tag, &.{}, nonce, key) catch |err| switch (err) {
            error.AuthenticationFailed => fatal("authentication failed", .{}),
        };

        return .{
            .entries = try parseEntries(alc, buf),
        };
    }

    // returned hash map holds references to slices in buf?
    fn parseEntries(alc: std.mem.Allocator, buf: []const u8) !std.StringArrayHashMapUnmanaged(Entry) {
        var r: std.Io.Reader = .fixed(buf);

        const entries_len = try r.takeInt(u16, .little);

        var entries: std.StringArrayHashMapUnmanaged(Entry) = .empty;
        try entries.ensureUnusedCapacity(alc, entries_len);

        for (0..entries_len) |_| {
            const created = try r.takeInt(i64, .little);
            const modified = try r.takeInt(i64, .little);
            const entry_name_len = try r.takeByte();
            const entry_name = try r.take(entry_name_len);
            const fields_len = try r.takeByte();

            var fields: std.StringArrayHashMapUnmanaged(Entry.Field) = .empty;
            try fields.ensureUnusedCapacity(alc, fields_len);

            for (0..fields_len) |_| {
                const secret = 1 == try r.takeByte();
                const name_len = try r.takeByte();
                const name = try r.take(name_len);
                const val_len = try r.takeInt(u16, .little);
                const val = try r.take(val_len);

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

    pub fn write(db: Database, writer: *std.Io.Writer, alc: std.mem.Allocator, key: [32]u8) !void {
        const buf = try db.serialize(alc);
        defer alc.free(buf);
        const ciphertext = try alc.alloc(u8, buf.len);
        defer alc.free(ciphertext);

        var tag: [16]u8 = undefined;
        var nonce: [32]u8 = undefined;
        try std.posix.getrandom(&nonce);
        Aegis256.encrypt(ciphertext, &tag, buf, &.{}, nonce, key);

        try writer.writeInt(u16, version, .little);
        try writer.writeAll(&tag);
        try writer.writeAll(&nonce);
        try writer.writeAll(ciphertext);
    }

    fn serialize(db: Database, alc: std.mem.Allocator) ![]const u8 {
        var aw: std.Io.Writer.Allocating = .init(alc);

        if (db.entries.count() > 1 << 16) fatal("more than {} entries in database", .{1 << 16});
        try aw.writer.writeInt(u16, @intCast(db.entries.count()), .little);
        for (db.entries.keys(), db.entries.values()) |entry_name, entry| {
            try aw.writer.writeInt(i64, entry.created, .little);
            try aw.writer.writeInt(i64, entry.modified, .little);
            if (entry_name.len > 1 << 8) fatal("entry '{s}' longer than {}", .{ entry_name, 1 << 8 });
            try aw.writer.writeByte(@intCast(entry_name.len));
            try aw.writer.writeAll(entry_name);
            if (entry.fields.count() > 1 << 8) fatal("more than {} fields in '{s}'", .{ 1 << 8, entry_name });
            try aw.writer.writeByte(@intCast(entry.fields.count()));

            for (entry.fields.keys(), entry.fields.values()) |field_name, field| {
                try aw.writer.writeByte(@intFromBool(field.secret));
                if (field_name.len > 1 << 8) fatal("field name '{s}' longer than {} in entry '{s}'", .{ field_name, 1 << 8, entry_name });
                try aw.writer.writeByte(@intCast(field_name.len));
                try aw.writer.writeAll(field_name);
                if (field.val.len > 1 << 16) fatal("value of field '{s}' in entry '{s}' is longer than {}", .{ field_name, entry_name, 1 << 16 });
                try aw.writer.writeInt(u16, @intCast(field.val.len), .little);
                try aw.writer.writeAll(field.val);
            }
        }
        return aw.toOwnedSlice();
    }
};

fn promptForPassword(alc: std.mem.Allocator) ![]const u8 {
    const stdin_file = std.fs.File.stdin();
    if (!stdin_file.isTty()) return error.NotATty;

    var stdin_reader = stdin_file.reader(&read_buffer);
    const stdin = &stdin_reader.interface;

    var stdout_writer = std.fs.File.stdout().writer(&write_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.writeAll("Password: ");
    try stdout.flush();

    const original_termios = std.posix.tcgetattr(stdin_file.handle) catch unreachable;
    var termios = original_termios;
    termios.lflag.ECHO = false;
    std.posix.tcsetattr(stdin_file.handle, .FLUSH, termios) catch unreachable;
    defer std.posix.tcsetattr(stdin_file.handle, .FLUSH, original_termios) catch unreachable;

    var aw: std.Io.Writer.Allocating = .init(alc);
    _ = stdin.streamDelimiterLimit(&aw.writer, '\n', .limited(4096)) catch |err| switch (err) {
        error.StreamTooLong => return error.PasswordTooLong,
        else => return err,
    };

    // clear line
    try stdout.writeAll("\x1b[G\x1b[K");
    try stdout.flush();

    return aw.toOwnedSlice();
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
