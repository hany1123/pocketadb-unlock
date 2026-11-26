//
//  PocketADBUnlock v2 — 基于真机探针数据的定向解锁
//
//  探针（PocketADB_probe.json）确认的事实：
//    class _TtC9PocketADB13PurchaseStore  EXISTS，ObjC 方法数 = 0（没有 -pro 之类可 swizzle 的东西）
//    _products                    0x10   @Published [Product]
//    _activeProProductIDs         0x20   @Published Set<String>   ← 视图真正读的权益集合
//    _isLoadingEntitlements       0x40   @Published Bool
//    _legacyAccess                0x50   @Published Bool          ← 老用户（legacy）直通开关
//    _confirmedLegacyUser         0x60   @Published Bool
//    entitlementRefreshTask       0x118
//    hasEntitlementSnapshot       0x120  Bool
//    hasUnverifiedProEntitlements 0x121  Bool
//    verifiedProProductIDs        0x128  Set<String>
//    unverifiedProProductIDs      0x130  Set<String>
//    legacyRefreshGeneration      0x140
//    hasLegacySnapshot            0x148  Bool
//
//  结论：真正决定能不能用 Pro 的是 activeProProductIDs / pro 这串路径，它不是函数而是
//  被内联进 SwiftUI body 的 Set 读取，静态补丁无处下手；而 Set<String> 又没法在 ObjC 里构造。
//  所以走"老用户直通"：把 legacyAccess / confirmedLegacyUser / hasEntitlementSnapshot /
//  hasLegacySnapshot 四个 Bool 置 1，这些是纯字节写入，安全、可回滚、不需要构造 Set。
//
//  取实例的办法：拦 swift_allocObject。Swift 类实例都经它分配，metadata 指针就是类对象本身。
//  做法是把主镜像 __got 里指向 swift_allocObject 的槽改写成自己的 thunk，无需 Substrate。
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/getsect.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <libkern/OSCacheControl.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>

typedef void *(*swift_alloc_fn)(const void *metadata, size_t size, size_t align);
static swift_alloc_fn g_real_alloc = NULL;
static Class g_store = Nil;
static void *g_instances[16];
static int g_instance_count = 0;
static NSMutableString *gLog = nil;

static void logline(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLog) gLog = [NSMutableString new];
    [gLog appendFormat:@"%@\n", s];
    NSLog(@"[PDBUnlock] %@", s);
    [gLog writeToFile:[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/PocketADB_unlock.log"]
           atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

// ---------- 实例捕获 ----------

static void remember_instance(void *obj) {
    for (int i = 0; i < g_instance_count; i++) {
        if (g_instances[i] == obj) return;
    }
    if (g_instance_count < 16) {
        g_instances[g_instance_count++] = obj;
        logline(@"captured PurchaseStore instance %p (#%d)", obj, g_instance_count);
    }
}

static void *pdb_alloc(const void *metadata, size_t size, size_t align) {
    void *obj = g_real_alloc ? g_real_alloc(metadata, size, align) : NULL;
    if (g_store && metadata == (__bridge const void *)g_store && obj) {
        remember_instance(obj);
    }
    return obj;
}

// ---------- 改写 __got 槽位 ----------

static BOOL hook_got_symbol(const char *symbol) {
    void *target = dlsym(RTLD_DEFAULT, symbol);
    if (!target) { logline(@"dlsym(%s) failed", symbol); return NO; }

    const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!hdr) return NO;
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);

    int hooked = 0;
    const struct load_command *lc = (const struct load_command *)((const uint8_t *)hdr + sizeof(*hdr));
    for (uint32_t i = 0; i < hdr->ncmds; i++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
        const struct section_64 *sect = (const struct section_64 *)((const uint8_t *)seg + sizeof(*seg));
        for (uint32_t s = 0; s < seg->nsects; s++, sect++) {
            if (strncmp(sect->sectname, "__got", 16) != 0 &&
                strncmp(sect->sectname, "__auth_got", 16) != 0) continue;
            uintptr_t base = (uintptr_t)(sect->addr + slide);
            size_t n = sect->size / sizeof(void *);
            void **slots = (void **)base;
            for (size_t k = 0; k < n; k++) {
                if (slots[k] == target) {
                    uintptr_t page = (uintptr_t)&slots[k] & ~(uintptr_t)0x3FFF;
                    vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false,
                               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                    slots[k] = (void *)&pdb_alloc;
                    sys_icache_invalidate(&slots[k], sizeof(void *));
                    hooked++;
                }
            }
        }
    }
    logline(@"hooked %s in %d __got slot(s)", symbol, hooked);
    return hooked > 0;
}

// ---------- 状态检查 & 写入 ----------

static Class find_store_class(void) {
    const char *names[] = { "PocketADB.PurchaseStore", "_TtC9PocketADB13PurchaseStore" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        Class c = objc_getClass(names[i]);
        if (c) return c;
    }
    return Nil;
}

static size_t set_count(void *obj, ptrdiff_t off) {
    uint8_t *p = (uint8_t *)obj + off;
    void *storage = *(void **)p;
    if (!storage) return 0;
    return *(size_t *)((uint8_t *)storage + 0x10);   // __RawSetStorage.count
}

static void apply_unlock(void) {
    if (!g_store || g_instance_count == 0) return;

    const char *names[] = { "legacyAccess", "confirmedLegacyUser", "hasEntitlementSnapshot",
                            "hasLegacySnapshot", "hasUnverifiedProEntitlements",
                            "verifiedProProductIDs", "unverifiedProProductIDs",
                            "activeProProductIDs" };
    ptrdiff_t offs[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };
    unsigned int n = 0;
    Ivar *ivars = class_copyIvarList(g_store, &n);
    for (unsigned int i = 0; i < n; i++) {
        const char *nm = ivar_getName(ivars[i]);
        if (!nm) continue;
        for (int k = 0; k < 8; k++) {
            if (strcmp(nm, names[k]) == 0) offs[k] = ivar_getOffset(ivars[i]);
        }
    }
    free(ivars);

    for (int k = 0; k < g_instance_count; k++) {
        uint8_t *o = (uint8_t *)g_instances[k];
        if (offs[0] >= 0) o[offs[0]] = 1;   // legacyAccess
        if (offs[1] >= 0) o[offs[1]] = 1;   // confirmedLegacyUser
        if (offs[2] >= 0) o[offs[2]] = 1;   // hasEntitlementSnapshot
        if (offs[3] >= 0) o[offs[3]] = 1;   // hasLegacySnapshot
        if (offs[4] >= 0) o[offs[4]] = 0;   // hasUnverifiedProEntitlements
    }

    static int ticks = 0;
    if (ticks++ % 8 == 0) {
        for (int k = 0; k < g_instance_count; k++) {
            logline(@"state[%d]: legacy=%d confirmed=%d entSnap=%d legacySnap=%d "
                    @"verifiedSet=%zu unverifiedSet=%zu activeSet=%zu",
                    k,
                    offs[0] >= 0 ? ((uint8_t *)g_instances[k])[offs[0]] : -1,
                    offs[1] >= 0 ? ((uint8_t *)g_instances[k])[offs[1]] : -1,
                    offs[2] >= 0 ? ((uint8_t *)g_instances[k])[offs[2]] : -1,
                    offs[3] >= 0 ? ((uint8_t *)g_instances[k])[offs[3]] : -1,
                    offs[5] >= 0 ? set_count(g_instances[k], offs[5]) : 0,
                    offs[6] >= 0 ? set_count(g_instances[k], offs[6]) : 0,
                    offs[7] >= 0 ? set_count(g_instances[k], offs[7]) : 0);
        }
    }
}

__attribute__((constructor))
static void pdbunlock_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        g_store = find_store_class();
        if (!g_store) { logline(@"PurchaseStore not found"); return; }
        logline(@"class %s @ %p instanceSize=%zu", class_getName(g_store), g_store,
                class_getInstanceSize(g_store));

        g_real_alloc = (swift_alloc_fn)dlsym(RTLD_DEFAULT, "swift_allocObject");
        if (!g_real_alloc) { logline(@"swift_allocObject not found"); return; }
        hook_got_symbol("swift_allocObject");

        // 每 0.4s 复查并重写（App 刷新权益时会把值改回去）
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                        dispatch_get_main_queue());
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 0),
                                  400ull * NSEC_PER_MSEC, 50ull * NSEC_PER_MSEC);
        dispatch_source_set_event_handler(timer, ^{ apply_unlock(); });
        dispatch_resume(timer);
    });
}
