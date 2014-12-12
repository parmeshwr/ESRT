/*
 * esrt.c
 *
 * This module exports EFI System Resource Table (ESRT) entries into 
userspace
 * through the sysfs file system. The ESRT provides a read-only catalog 
of
 * system components for which the system accepts firmware upgrades via 
UEFI's
 * "Capsule Update" feature. This module allows userland utilities to 
evaluate
 * what firmware updates can be applied to this system, and potentially 
arrange
 * for those updates to occur.
 *
 * Data is currently found below /sys/firmware/efi/esrt/...
 */
#define pr_fmt(fmt) "esrt: " fmt

#include <linux/capability.h>
#include <linux/device.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

struct efi_system_resource_entry {
	efi_guid_t	fw_class;
	u32		fw_type;
	u32		fw_version;
	u32		lowest_supported_fw_version;
	u32		capsule_flags;
	u32		last_attempt_version;
	u32		last_attempt_status;
};

/*
 * _count and _version are what they seem like.  _max is actually just
 * accounting info for the firmware when creating the table; it should 
never
 * have been exposed to us.  To wit, the spec says:
 * The maximum number of resource array entries that can be within the
 * table without reallocating the table, must not be zero.
 * Since there's no guidance about what that means in terms of memory 
layout,
 * it means nothing to us.
 */
struct efi_system_resource_table {
	u32	fw_resource_count;
	u32	fw_resource_count_max;
	u64	fw_resource_version;
	struct efi_system_resource_entry entries[]; };

static struct efi_system_resource_table *esrt;

struct esre_entry {
	struct efi_system_resource_entry *esre;

	struct kobject kobj;
	struct list_head list;
};

/* global list of esre_entry. */
static LIST_HEAD(entry_list);

/* entry attribute */
struct esre_attribute {
	struct attribute attr;
	ssize_t (*show)(struct esre_entry *entry, char *buf);
	ssize_t (*store)(struct esre_entry *entry,
			 const char *buf, size_t count);
};

static struct esre_entry *to_entry(struct kobject *kobj) {
	return container_of(kobj, struct esre_entry, kobj); }

static struct esre_attribute *to_attr(struct attribute *attr) {
	return container_of(attr, struct esre_attribute, attr); }

static ssize_t esre_attr_show(struct kobject *kobj,
			      struct attribute *_attr, char *buf) {
	struct esre_entry *entry = to_entry(kobj);
	struct esre_attribute *attr = to_attr(_attr);

	/* Don't tell normal users what firmware versions we've got... */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	return attr->show(entry, buf);
}

static const struct sysfs_ops esre_attr_ops = {
	.show = esre_attr_show,
};

/* Generic ESRT Entry ("ESRE") support. */ static ssize_t 
esre_fw_class_show(struct esre_entry *entry, char *buf) {
	char *str = buf;

	efi_guid_unparse(&entry->esre->fw_class, str);
	str += strlen(str);
	str += sprintf(str, "\n");

	return str - buf;
}

static struct esre_attribute esre_fw_class = __ATTR(fw_class, 0400,
	esre_fw_class_show, NULL);

#define esre_attr_decl(name, size, fmt) \
static ssize_t esre_##name##_show (struct esre_entry *entry, char *buf) \
{\
	return sprintf(buf, fmt "\n", le##size##_to_cpu(entry->esre->name));\
}\
static struct esre_attribute esre_##name = __ATTR(name, 0400,\
	esre_##name##_show, NULL)

esre_attr_decl(fw_type, 32, "%u");
esre_attr_decl(fw_version, 32, "%u");
esre_attr_decl(lowest_supported_fw_version, 32, "%u"); 
esre_attr_decl(capsule_flags, 32, "0x%x"); 
esre_attr_decl(last_attempt_version, 32, "%u"); 
esre_attr_decl(last_attempt_status, 32, "%u");

static struct attribute *esre_attrs[] = {
	&esre_fw_class.attr,
	&esre_fw_type.attr,
	&esre_fw_version.attr,
	&esre_lowest_supported_fw_version.attr,
	&esre_capsule_flags.attr,
	&esre_last_attempt_version.attr,
	&esre_last_attempt_status.attr,
	NULL
};

static void esre_release(struct kobject *kobj) {
	struct esre_entry *entry = to_entry(kobj);

	list_del(&entry->list);
	kfree(entry);
}

static struct kobj_type esre_ktype = {
	.release = esre_release,
	.sysfs_ops = &esre_attr_ops,
	.default_attrs = esre_attrs,
};

static struct kobject *esrt_kobj;
static struct kset *esrt_kset;

static int esre_create_sysfs_entry(struct efi_system_resource_entry 
*esre) {
	int rc;
	struct esre_entry *entry;
	char name[EFI_VARIABLE_GUID_LEN + 1];

	printk("PARAM %s\n",__func__);
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	efi_guid_unparse(&esre->fw_class, name);

	entry->esre = esre;
	entry->kobj.kset = esrt_kset;
	rc = kobject_init_and_add(&entry->kobj, &esre_ktype, NULL,
				  "%s", name);
	if (rc) {
		kfree(entry);
		return rc;
	}

	list_add_tail(&entry->list, &entry_list);
	printk("PARAM %s\n",__func__);
	return 0;
}

/* support for displaying ESRT fields at the top level */ 
#define esrt_attr_decl(name, size, fmt)\
static ssize_t esrt_##name##_show(struct kobject *kobj,struct kobj_attribute *attr, char *buf) \
{\
	return sprintf(buf, fmt "\n", le##size##_to_cpu(esrt->name));\
}\
static struct kobj_attribute esrt_##name = __ATTR(name, 0400, esrt_##name##_show, NULL)

esrt_attr_decl(fw_resource_count, 32, "%u"); 
esrt_attr_decl(fw_resource_count_max, 32, "%u"); 
esrt_attr_decl(fw_resource_version, 64, "%llu");

static struct attribute *esrt_attrs[] = {
	&esrt_fw_resource_count.attr,
	&esrt_fw_resource_count_max.attr,
	&esrt_fw_resource_version.attr,
	NULL,
};

static inline int esrt_table_exists(void) {
	if (!efi_enabled(EFI_CONFIG_TABLES))
		return 0;
	if (efi.esrt == EFI_INVALID_TABLE_ADDR)
		return 0;
	return 1;
}

static umode_t esrt_attr_is_visible(struct kobject *kobj,
				    struct attribute *attr, int n)
{
	if (!esrt_table_exists())
		return 0;
	return attr->mode;
}

static struct attribute_group esrt_attr_group = {
	.attrs = esrt_attrs,
	.is_visible = esrt_attr_is_visible,
};

/*
 * ioremap the table, copy it to kmalloced pages, and unmap it.
 */
static int esrt_duplicate_pages(void)
{
	struct efi_system_resource_table *tmpesrt;
	struct efi_system_resource_entry *entries;
	size_t size, max;
	int err = -EINVAL;

	printk("PARAM %s\n",__func__);
	if (!esrt_table_exists())
		return err;

	max = efi_mem_max_reasonable_size(efi.esrt);
	if (max < 0) {
		pr_err("ESRT header is not in the memory map.\n");
		return err;
	}
	size = sizeof(*esrt);

	if (max < size) {
		pr_err("ESRT header doen't fit on single memory map entry.\n");
		return err;
	}

	tmpesrt = ioremap(efi.esrt, size);
	if (!tmpesrt) {
		pr_err("ioremap failed.\n");
		return -ENOMEM;
	}

	if (tmpesrt->fw_resource_count > 0 && max - size < sizeof(*entries)) {
		pr_err("ESRT memory map entry can only hold the header.\n");
		goto err_iounmap;
	}

	/*
	 * The format doesn't really give us any boundary to test here,
	 * so I'm making up 128 as the max number of individually updatable
	 * components we support.
	 * 128 should be pretty excessive, but there's still some chance
	 * somebody will do that someday and we'll need to raise this.
	 */
	if (tmpesrt->fw_resource_count > 128) {
		pr_err("ESRT says fw_resource_count has very large value %d.\n",
		       tmpesrt->fw_resource_count);
		goto err_iounmap;
	}

	/*
	 * We know it can't be larger than N * sizeof() here, and N is limited
	 * by the previous test to a small number, so there's no overflow.
	 */
	size += tmpesrt->fw_resource_count * sizeof(*entries);
	if (max < size) {
		pr_err("ESRT does not fit on single memory map entry.\n");
		goto err_iounmap;
	}

	esrt = kmalloc(size, GFP_KERNEL);
	if (!esrt) {
		err = -ENOMEM;
		goto err_iounmap;
	}

	memcpy(esrt, tmpesrt, size);
	err = 0;
	printk("PARAM %s\n",__func__);
err_iounmap:
	printk("PARAM %s\n",__func__);
	iounmap(tmpesrt);
	return err;
}

static int register_entries(void)
{
	struct efi_system_resource_entry *entries = esrt->entries;
	int i, rc;

	printk("PARAM %s\n",__func__);
	if (!esrt_table_exists())
		return 0;

	for (i = 0; i < le32_to_cpu(esrt->fw_resource_count); i++) {
		rc = esre_create_sysfs_entry(&entries[i]);
		if (rc < 0) {
			pr_err("ESRT entry creation failed with error %d.\n",
			       rc);
			return rc;
		}
	}
	printk("PARAM %s\n",__func__);
	return 0;
}

static void cleanup_entry_list(void)
{
	struct esre_entry *entry, *next;

	printk("PARAM %s\n",__func__);
	list_for_each_entry_safe(entry, next, &entry_list, list) {
		kobject_put(&entry->kobj);
	}
}

static int __init esrt_sysfs_init(void) {
	int error;
	printk("PARAM %s\n",__func__);
	error = esrt_duplicate_pages();
	if (error)
		return error;

	esrt_kobj = kobject_create_and_add("esrt", efi_kobj);
	if (!esrt_kobj) {
		pr_err("Firmware table registration failed.\n");
		error = -ENOMEM;
		goto err;
	}

	error = sysfs_create_group(esrt_kobj, &esrt_attr_group);
	if (error) {
		pr_err("Sysfs attribute export failed with error %d.\n",
		       error);
		goto err_remove_esrt;
	}

	esrt_kset = kset_create_and_add("entries", NULL, esrt_kobj);
	if (!esrt_kset) {
		pr_err("kset creation failed.\n");
		error = -ENOMEM;
		goto err_remove_group;
	}

	error = register_entries();
	if (error)
		goto err_cleanup_list;

	pr_debug("esrt-sysfs: loaded.\n");

	printk("PARAM %s\n",__func__);
	return 0;
err_cleanup_list:
	printk("PARAM %s\n",__func__);
	cleanup_entry_list();
	kset_unregister(esrt_kset);
err_remove_group:
	printk("PARAM %s\n",__func__);
	sysfs_remove_group(esrt_kobj, &esrt_attr_group);
err_remove_esrt:
	printk("PARAM %s\n",__func__);
	kobject_put(esrt_kobj);
err:
	printk("PARAM %s\n",__func__);
	kfree(esrt);
	esrt = NULL;
	return error;
}

static void __exit esrt_sysfs_exit(void) {
	pr_debug("esrt-sysfs: unloading.\n");
	cleanup_entry_list();
	kset_unregister(esrt_kset);
	sysfs_remove_group(esrt_kobj, &esrt_attr_group);
	kfree(esrt);
	esrt = NULL;
	kobject_del(esrt_kobj);
	kobject_put(esrt_kobj);
}

module_init(esrt_sysfs_init);
module_exit(esrt_sysfs_exit);

MODULE_AUTHOR("Peter Jones <pjones@redhat.com>"); 
MODULE_DESCRIPTION("EFI System Resource Table support"); 
MODULE_LICENSE("GPL");
