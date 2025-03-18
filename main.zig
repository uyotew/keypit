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
    \\     it's value will be retrieved by default
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
    \\     if you wish to generate the secret in another way, you can use
    \\     for example: fieldname=??a30
    \\     where you add an extra ?, and 'a' means alphanumeric,
    \\     and the number is the amount of characters to be generated.
    \\     'p' and 'e' works also, where 'p' is all printable characters,
    \\     and 'e' is every byte from 0 to 255.
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
    var subcommand_opt: ?enum { get, show, modify, new, remove } = null;
    var pairs: std.ArrayList(struct { name: []const u8, val: []const u8 }) = .init(arena);
    var entry_name: ?[]const u8 = null;
    var field_name: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "--help")) {
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
        } else if (subcommand_opt == null and std.mem.eql(u8, args[i], "remove")) {
            subcommand_opt = .remove;
        } else if (subcommand_opt != null and entry_name == null) {
            entry_name = args[i];
        } else if (subcommand_opt) |sub| {
            switch (sub) {
                .get => {
                    if (field_name != null) fatal("unrecognized argument '{s}'", .{args[i]});
                    field_name = args[i];
                },
                .modify, .new => if (std.mem.indexOfScalar(u8, args[i], '=')) |eq_i| {
                    try pairs.append(.{
                        .name = args[i][0..eq_i],
                        .val = args[i][eq_i + 1 ..],
                    });
                } else fatal("unrecognized argument '{s}'", .{args[i]}),
                .remove, .show => fatal("unrecognized argument '{s}'", .{args[i]}),
            }
        } else fatal("unrecognized subcommand '{s}'", .{args[i]});
    }
    const subcommand = subcommand_opt orelse fatal("expected subcommand", .{});
    switch (subcommand) {
        .show => {},
        .modify, .new, .get, .remove => {
            if (entry_name == null) fatal("subcommand '{s}' expects an entry name", .{@tagName(subcommand)});
        },
    }

    const filepath = if (filepath_opt) |f| f else blk: {
        const xdg_data_home = std.posix.getenv("XDG_DATA_HOME") orelse fatal("XDG_DATA_HOME is undefined", .{});
        break :blk try std.fs.path.join(arena, &.{ xdg_data_home, "keypit.db" });
    };

    const file = std.fs.cwd().openFile(filepath, .{}) catch |err| switch (err) {
        error.FileNotFound => switch (subcommand) {
            .modify, .show, .get, .remove => {
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
                for (database.entries.items) |e| {
                    if (std.mem.eql(u8, name, e.name)) {
                        try stdout.print("{}\n", .{e});
                        std.process.exit(0);
                    }
                } else fatal("entry '{s}' not found", .{name});
            } else {
                for (database.entries.items) |e| try stdout.print("{}\n", .{e});
                std.process.exit(0);
            }
        },
        .get => {
            for (database.entries.items) |e| {
                if (std.mem.eql(u8, entry_name.?, e.name)) {
                    var value: []const u8 = undefined;
                    if (field_name) |f_n| {
                        for (e.fields.items) |f| {
                            if (std.mem.eql(u8, f.name, f_n)) {
                                value = f.val;
                                break;
                            }
                        } else fatal("field '{s}' not found", .{f_n});
                    } else {
                        var secret_fields: u8 = 0;
                        for (e.fields.items) |f| {
                            if (f.secret) {
                                value = f.val;
                                secret_fields += 1;
                            }
                        }
                        if (secret_fields != 1) fatal("not exactly one secret field, fieldname need to be provided", .{});
                    }

                    if (use_clipboard) {
                        var proc = std.process.Child.init(&.{ "wl-copy", value }, arena);
                        _ = proc.spawnAndWait() catch |err| switch (err) {
                            error.FileNotFound => fatal("wl-copy could not be found", .{}),
                            else => return err,
                        };
                    } else {
                        try stdout.print("{s}\n", .{value});
                    }
                    std.process.exit(0);
                }
            } else fatal("entry '{s}' not found", .{entry_name.?});
        },
        .remove => {
            for (database.entries.items, 0..) |e, e_i| {
                if (std.mem.eql(u8, entry_name.?, e.name)) {
                    _ = database.entries.swapRemove(e_i);
                    break;
                }
            } else fatal("entry '{s}' not found", .{entry_name.?});
        },
        .new => {
            for (database.entries.items) |e| {
                if (std.mem.eql(u8, entry_name.?, e.name)) fatal("entry name '{s}' already in use", .{entry_name.?});
            }
            const timestamp = std.time.timestamp();
            var entry: Database.Entry = .{
                .created = timestamp,
                .modified = timestamp,
                .name = entry_name.?,
            };
            for (pairs.items, 0..) |p, p_i| {
                for (pairs.items[0..p_i]) |prev_p| {
                    if (std.mem.eql(u8, p.name, prev_p.name)) fatal("field '{s}' appears more than once", .{p.name});
                }
                if (p.val.len == 0) fatal("field '{s}' is empty, no empty values allowed", .{p.name});
                try entry.fields.append(arena, try .fromRaw(arena, p.name, p.val));
            }
            try database.entries.append(arena, entry);
        },
        .modify => {
            const e_i = for (database.entries.items, 0..) |e, e_i| {
                if (std.mem.eql(u8, entry_name.?, e.name)) break e_i;
            } else fatal("entry '{s}' not found", .{entry_name.?});
            const entry = &database.entries.items[e_i];
            entry.modified = std.time.timestamp();

            for (pairs.items, 0..) |p, p_i| {
                for (pairs.items[0..p_i]) |prev_p| {
                    if (std.mem.eql(u8, p.name, prev_p.name)) fatal("field '{s}' appears more than once", .{p.name});
                }
                const f_i: ?usize = for (entry.fields.items, 0..) |f, f_i| {
                    if (std.mem.eql(u8, f.name, p.name)) break f_i;
                } else null;

                if (p.val.len == 0) {
                    if (f_i == null) fatal("cannot remove '{s}', since it doesn't exist", .{p.name});
                    _ = entry.fields.swapRemove(f_i.?);
                    break;
                }
                if (f_i) |fi| {
                    entry.fields.items[fi] = try .fromRaw(arena, p.name, p.val);
                } else {
                    try entry.fields.append(arena, try .fromRaw(arena, p.name, p.val));
                }
            }
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
    entries: std.ArrayListUnmanaged(Entry) = .{},
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
        name: []const u8,
        fields: std.ArrayListUnmanaged(Field) = .{},

        const Field = struct {
            secret: bool = false,
            name: []const u8,
            val: []const u8,

            fn fromRaw(arena: std.mem.Allocator, name: []const u8, raw_val: []const u8) !Field {
                var val: []u8 = try arena.dupe(u8, raw_val);
                // default generated value
                if (raw_val.len == 1 and raw_val[0] == '?') {
                    val = try arena.alloc(u8, 64);
                    try generateSecret(val, .printable);
                } else if (raw_val[0] == '?' and raw_val[1] == '?') {
                    if (raw_val.len < 3) fatal("expected either 'e', 'a' or 'p' after {s}=??", .{name});
                    if (raw_val.len < 4) fatal("expected a number (length) after {s}={s}", .{ name, raw_val });
                    const len = std.fmt.parseInt(u16, raw_val[3..], 10) catch |err| switch (err) {
                        error.Overflow => fatal("{s}={s} length cannot be bigger than a u16", .{ name, raw_val }),
                        error.InvalidCharacter => fatal("expected a number (length) after {s}={s}", .{ name, raw_val[0..3] }),
                    };
                    val = try arena.alloc(u8, len);
                    try generateSecret(val, switch (raw_val[2]) {
                        'e' => .every,
                        'a' => .alphanumeric,
                        'p' => .printable,
                        else => fatal("expected either 'e', 'a' or 'p' after {s}=??", .{name}),
                    });
                } else if (raw_val[0] == '?') {
                    val = val[1..];
                }
                return .{
                    .secret = raw_val[0] == '?',
                    .name = name,
                    .val = val,
                };
            }
        };

        pub fn format(e: Entry, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.writeAll(e.name);
            try writer.writeByte('\n');
            try writer.writeAll(" created: ");
            try dateFormat(e.created, writer);
            try writer.writeByte('\n');
            try writer.writeAll(" modified: ");
            try dateFormat(e.modified, writer);
            try writer.writeByte('\n');

            for (e.fields.items) |f| {
                try writer.print("  {s}: ", .{f.name});
                if (f.secret) {
                    try writer.writeByteNTimes('*', f.val.len);
                } else {
                    try writer.print("{s}", .{f.val});
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

    // returned array list holds references to slices in buf
    fn parseEntries(alc: std.mem.Allocator, buf: []const u8) !std.ArrayListUnmanaged(Entry) {
        var i: usize = 0;
        const entries_len = std.mem.readInt(u16, buf[i..][0..2], .little);
        i += 2;
        var entries = try std.ArrayListUnmanaged(Entry).initCapacity(alc, entries_len);

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
            var fields = try std.ArrayListUnmanaged(Entry.Field).initCapacity(alc, fields_len);

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
                fields.appendAssumeCapacity(.{
                    .secret = secret,
                    .name = name,
                    .val = val,
                });
            }
            entries.appendAssumeCapacity(.{
                .created = created,
                .modified = modified,
                .name = entry_name,
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
        if (db.entries.items.len > 1 << 16) fatal("more than {} entries in database", .{1 << 16});
        try writer.writeInt(u16, @intCast(db.entries.items.len), .little);
        for (db.entries.items) |entry| {
            try writer.writeInt(i64, entry.created, .little);
            try writer.writeInt(i64, entry.modified, .little);
            if (entry.name.len > 1 << 8) fatal("entry '{s}' longer than {}", .{ entry.name, 1 << 8 });
            try writer.writeByte(@intCast(entry.name.len));
            try writer.writeAll(entry.name);
            if (entry.fields.items.len > 1 << 8) fatal("more than {} fields in '{s}'", .{ 1 << 8, entry.name });
            try writer.writeByte(@intCast(entry.fields.items.len));

            for (entry.fields.items) |field| {
                try writer.writeByte(@intFromBool(field.secret));
                if (field.name.len > 1 << 8) fatal("field name '{s}' longer than {} in entry '{s}'", .{ field.name, 1 << 8, entry.name });
                try writer.writeByte(@intCast(field.name.len));
                try writer.writeAll(field.name);
                if (field.val.len > 1 << 16) fatal("value of field '{s}' in entry '{s}' is longer than {}", .{ field.name, entry.name, 1 << 16 });
                try writer.writeInt(u16, @intCast(field.val.len), .little);
                try writer.writeAll(field.val);
            }
        }
        return list.toOwnedSlice();
    }

    pub fn attributeNames(db: Database, alc: std.mem.Allocator) ![]const u8 {
        var list = std.ArrayList([]const u8).init(alc);
        for (db.entries.items) |e| {
            for (e.fields.items) |f| {
                try list.append(f.name);
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

test Database {
    _ = std.testing.allocator;
}

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

fn generateSecret(out: []u8, char_set: enum { printable, alphanumeric, every }) !void {
    try std.posix.getrandom(out);
    switch (char_set) {
        .every => {},
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
