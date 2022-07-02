#include "pan_base.h"
#include "internal.h"

bool kbase_open_csf(kbase k);

static bool
open_kbase(kbase k)
{
        k->fd = open("/dev/mali0", O_RDWR);
        if (k->fd != -1)
                return true;

        perror("open(\"/dev/mali0\")");
        return false;
}

static bool
close_kbase(kbase k)
{
        int pid = getpid();
        char cmd_buffer[64] = {0};
        sprintf(cmd_buffer, "grep /dev/mali /proc/%i/maps", pid);
        system(cmd_buffer);
        sprintf(cmd_buffer, "ls -l /proc/%i/fd", pid);
        system(cmd_buffer);

        if (k->fd > 0)
                return close(k->fd) == 0;
        return true;
}

static bool
get_version(kbase k)
{
        struct kbase_ioctl_version_check ver = { 0 };

        int ret = ioctl(k->fd, KBASE_IOCTL_VERSION_CHECK, &ver);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_VERSION_CHECK)");
                return false;
        }

        printf("Major %i Minor %i: ", ver.major, ver.minor);
        return true;
}

static bool
set_flags(kbase k)
{
        struct kbase_ioctl_set_flags flags = {
                .create_flags = 0
        };

        int ret = ioctl(k->fd, KBASE_IOCTL_SET_FLAGS, &flags);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_SET_FLAGS)");
                return false;
        }
        return true;
}

static bool
mmap_tracking(kbase k)
{
        k->tracking_region = mmap(NULL, k->page_size, PROT_NONE,
                                  MAP_SHARED, k->fd,
                                  BASE_MEM_MAP_TRACKING_HANDLE);

        if (k->tracking_region == MAP_FAILED) {
                perror("mmap(BASE_MEM_MAP_TRACKING_HANDLE)");
                k->tracking_region = NULL;
                return false;
        }
        return true;
}

static bool
munmap_tracking(kbase k)
{
        if (k->tracking_region)
                return munmap(k->tracking_region, k->page_size) == 0;
        return true;
}

static bool
get_gpuprops(kbase k)
{
        struct kbase_ioctl_get_gpuprops props = { 0 };

        int ret = ioctl(k->fd, KBASE_IOCTL_GET_GPUPROPS, &props);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_GET_GPUPROPS(0))");
                return false;
        } else if (!ret) {
                fprintf(stderr, "GET_GPUPROPS returned zero size\n");
                return false;
        }

        k->gpuprops_size = ret;
        k->gpuprops = calloc(k->gpuprops_size, 1);

        props.size = k->gpuprops_size;
        props.buffer = (uint64_t)(uintptr_t) k->gpuprops;

        ret = ioctl(k->fd, KBASE_IOCTL_GET_GPUPROPS, &props);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_GET_GPUPROPS(size))");
                return false;
        }

        return true;
}

static bool
free_gpuprops(kbase k)
{
        free(k->gpuprops);
        return true;
}

static bool
get_gpu_id(kbase k)
{
        uint64_t gpu_id = pan_get_gpuprop(s, KBASE_GPUPROP_PRODUCT_ID);
        if (!gpu_id)
                return false;
        k->gpu_id = gpu_id;

        uint16_t maj = gpu_id >> 12;
        uint16_t min = (gpu_id >> 8) & 0xf;
        uint16_t rev = (gpu_id >> 4) & 0xf;
        uint16_t product = gpu_id & 0xf;

        const char *names[] = {
                [0] = "G610",
                [8] = "G710",
                [10] = "G510",
                [12] = "G310",
        };
        const char *name = (min < ARRAY_SIZE(names)) ? names[min] : NULL;
        if (!name)
                name = "unknown";

        printf("v%i.%i r%ip%i (Mali-%s): ", maj, min, rev, product, name);

        if (maj < 10) {
                printf("not v10 or later: ");
                return false;
        }

        return true;
}

static bool
get_coherency_mode(kbase k)
{
        uint64_t mode = pan_get_gpuprop(s, KBASE_GPUPROP_RAW_COHERENCY_MODE);

        const char *modes[] = {
                [0] = "ACE-Lite",
                [1] = "ACE",
                [31] = "None",
        };
        const char *name = (mode < ARRAY_SIZE(modes)) ? modes[mode] : NULL;
        if (!name)
                name = "Unknown";

        printf("0x%"PRIx64" (%s): ", mode, name);
        return true;
}

static bool
get_csf_caps(kbase k)
{
        union kbase_ioctl_cs_get_glb_iface iface = { 0 };

        int ret = ioctl(k->fd, KBASE_IOCTL_CS_GET_GLB_IFACE, &iface);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_GET_GLB_IFACE(0))");
                return false;
        }

        printf("v%i: feature mask 0x%x, %i groups, %i total: ",
               iface.out.glb_version, iface.out.features,
               iface.out.group_num, iface.out.total_stream_num);

        unsigned group_num = iface.out.group_num;
        unsigned stream_num = iface.out.total_stream_num;

        struct basep_cs_group_control *group_data =
                calloc(group_num, sizeof(*group_data));

        struct basep_cs_stream_control *stream_data =
                calloc(stream_num, sizeof(*stream_data));

        iface = (union kbase_ioctl_cs_get_glb_iface) {
                .in = {
                        .max_group_num = group_num,
                        .max_total_stream_num = stream_num,
                        .groups_ptr = (uintptr_t) group_data,
                        .streams_ptr = (uintptr_t) stream_data,
                }
        };

        ret = ioctl(k->fd, KBASE_IOCTL_CS_GET_GLB_IFACE, &iface);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_GET_GLB_IFACE(size))");

                free(group_data);
                free(stream_data);

                return false;
        }

        for (unsigned i = 0; i < group_num; ++i) {
                if (i && !memcmp(group_data + i, group_data + i - 1, sizeof(*group_data)))
                        continue;

                fprintf(stderr, "Group %i-: feature mask 0x%x, %i streams\n",
                        i, group_data[i].features, group_data[i].stream_num);
        }

        for (unsigned i = 0; i < stream_num; ++i) {
                if (i && !memcmp(stream_data + i, stream_data + i - 1, sizeof(*stream_data)))
                        continue;

                fprintf(stderr, "Stream %i-: feature mask 0x%x\n",
                        i, stream_data[i].features);
        }

        free(group_data);
        free(stream_data);

        return true;
}

static bool
mmap_user_reg(kbase k)
{
        k->csf_user_reg = mmap(NULL, k->page_size, PROT_READ,
                               MAP_SHARED, k->fd,
                               BASEP_MEM_CSF_USER_REG_PAGE_HANDLE);

        if (k->csf_user_reg == MAP_FAILED) {
                perror("mmap(BASEP_MEM_CSF_USER_REG_PAGE_HANDLE)");
                k->csf_user_reg = NULL;
                return false;
        }
        return true;
}

static bool
munmap_user_reg(kbase k)
{
        if (k->csf_user_reg)
                return munmap(k->csf_user_reg, k->page_size) == 0;
        return true;
}

static bool
init_mem_exec(kbase k)
{
        struct kbase_ioctl_mem_exec_init init = {
                .va_pages = 0x100000,
        };

        int ret = ioctl(k->fd, KBASE_IOCTL_MEM_EXEC_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_EXEC_INIT)");
                return false;
        }
        return true;
}

static bool
init_mem_jit(kbase k)
{
        struct kbase_ioctl_mem_jit_init init = {
                .va_pages = 1 << 25,
                .max_allocations = 255,
                .phys_pages = 1 << 25,
        };

        int ret = ioctl(k->fd, KBASE_IOCTL_MEM_JIT_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_JIT_INIT)");
                return false;
        }
        return true;
}
