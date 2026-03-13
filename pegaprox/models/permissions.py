# -*- coding: utf-8 -*-
"""
PegaProx Permissions & Roles - Layer 0
No pegaprox imports allowed.
"""

# User roles
ROLE_ADMIN = 'admin'
ROLE_USER = 'user'
ROLE_VIEWER = 'viewer'

# Builtin roles - cannot be deleted
BUILTIN_ROLES = [ROLE_ADMIN, ROLE_USER, ROLE_VIEWER]

PERMISSIONS = {
    # vm stuff
    'vm.view': 'View VMs and containers',
    'vm.start': 'Start VMs and containers',
    'vm.stop': 'Stop VMs and containers',
    'vm.restart': 'Restart VMs and containers',
    'vm.console': 'Access VM console',
    'vm.migrate': 'Migrate VMs between nodes',
    'vm.clone': 'Clone VMs',
    'vm.delete': 'Delete VMs and containers',
    'vm.create': 'Create new VMs and containers',
    'vm.config': 'Modify VM configuration',
    'vm.snapshot': 'Create/delete snapshots',
    'vm.backup': 'Backup VMs',
    'vm.template': 'Convert to/from template',

    # Cluster permissions
    'cluster.view': 'View cluster info',
    'cluster.add': 'Add new clusters',
    'cluster.delete': 'Remove clusters',
    'cluster.config': 'Modify cluster settings',
    'cluster.join': 'Join nodes to cluster',
    'cluster.admin': 'Full cluster administration (join/remove nodes)',

    # Node permissions
    'node.view': 'View node status',
    'node.shell': 'Access node shell',
    'node.maintenance': 'Toggle maintenance mode',
    'node.update': 'Update node packages',
    'node.reboot': 'Reboot nodes',
    'node.network': 'Modify network config',
    'node.config': 'Change node options',
    'node.certificate': 'Manage SSL certificates',
    'node.power': 'Shutdown/wake nodes',

    # Storage permissions
    'storage.view': 'View storage',
    'storage.upload': 'Upload files to storage',
    'storage.delete': 'Delete files from storage',
    'storage.config': 'Modify storage config',
    'storage.create': 'Add new storage',
    'storage.download': 'Download ISOs/templates',

    # Backup permissions
    'backup.view': 'View backups',
    'backup.create': 'Create backups',
    'backup.restore': 'Restore from backup',
    'backup.delete': 'Delete backups',
    'backup.schedule': 'Manage backup schedules',
    'backup.config': 'Configure backup storage',

    # HA permissions
    'ha.view': 'View HA status',
    'ha.config': 'Configure HA settings',
    'ha.groups': 'Manage HA groups',
    'ha.resources': 'Add/remove HA resources',

    # Firewall permissions
    'firewall.view': 'View firewall rules',
    'firewall.edit': 'Modify firewall rules',
    'firewall.aliases': 'Manage aliases/IPsets',

    # Pool/Resource permissions
    'pool.view': 'View resource pools',
    'pool.manage': 'Create/delete pools',
    'pool.assign': 'Assign VMs to pools',

    # Replication
    'replication.view': 'View replication jobs',
    'replication.manage': 'Create/delete replication',

    # Admin permissions
    'admin.users': 'Manage users',
    'admin.roles': 'Manage custom roles',
    'admin.tenants': 'Manage tenants',
    'admin.groups': 'Manage cluster groups',
    'admin.settings': 'Modify system settings',
    'admin.scripts': 'Manage and execute custom scripts',
    'admin.audit': 'View audit logs',
    'admin.api': 'Manage API tokens',

    # PBS permissions
    'pbs.view': 'View PBS servers and datastores',
    'pbs.config': 'Modify PBS server settings',
    'pbs.datastore.view': 'View datastore details and snapshots',
    'pbs.datastore.create': 'Create new datastores on PBS',
    'pbs.datastore.modify': 'Modify datastore configuration',
    'pbs.datastore.delete': 'Delete datastores from PBS',
    'pbs.datastore.gc': 'Run garbage collection on datastores',
    'pbs.datastore.verify': 'Run verification on datastores',
    'pbs.datastore.prune': 'Prune snapshots from datastores',
    'pbs.snapshot.delete': 'Delete individual snapshots',
    'pbs.snapshot.protect': 'Toggle snapshot protection',
    'pbs.snapshot.notes': 'Edit snapshot/group notes',
    'pbs.snapshot.browse': 'Browse and download snapshot files',
    'pbs.jobs.view': 'View sync/verify/prune jobs',
    'pbs.jobs.run': 'Manually trigger jobs',
    'pbs.tasks.view': 'View PBS tasks',
    'pbs.tasks.stop': 'Stop running PBS tasks',
    'pbs.jobs.create': 'Create sync/verify/prune jobs',
    'pbs.jobs.modify': 'Modify existing jobs',
    'pbs.jobs.delete': 'Delete jobs',
    'pbs.notifications.view': 'View notification config',
    'pbs.notifications.manage': 'Create/modify/delete notifications',
    'pbs.traffic.view': 'View traffic control config',
    'pbs.traffic.manage': 'Create/modify/delete traffic controls',
    'pbs.disks.view': 'View disk information',
    'pbs.disks.smart': 'View disk SMART data',
    'pbs.subscription.view': 'View subscription status',
    'pbs.subscription.set': 'Set subscription key',

    # VMware/vCenter permissions
    'vmware.view': 'View vCenter/ESXi servers',
    'vmware.config': 'Add/edit/remove vCenter connections',
    'vmware.vm.view': 'View VMware VMs and details',
    'vmware.vm.power': 'Start/stop/restart VMware VMs',
    'vmware.vm.snapshot': 'Create/delete VMware VM snapshots',
    'vmware.vm.migrate': 'Migrate VMs to Proxmox (V2V)',
    'vmware.host.view': 'View ESXi host details',
    'vmware.datastore.view': 'View VMware datastores',
    'vmware.network.view': 'View VMware networks',
}

# Default permissions per role
ROLE_PERMISSIONS = {
    ROLE_ADMIN: list(PERMISSIONS.keys()),
    ROLE_USER: [
        'vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console', 'vm.migrate',
        'vm.clone', 'vm.config', 'vm.snapshot', 'vm.backup',
        'cluster.view',
        'node.view',
        'storage.view', 'storage.upload', 'storage.download',
        'backup.view', 'backup.create', 'backup.restore', 'backup.delete',
        'ha.view',
        'firewall.view',
        'pool.view', 'pool.assign',
        'replication.view',
        'pbs.view', 'pbs.datastore.view', 'pbs.datastore.gc', 'pbs.datastore.verify',
        'pbs.snapshot.notes', 'pbs.snapshot.browse',
        'pbs.jobs.view', 'pbs.tasks.view',
        'pbs.notifications.view', 'pbs.traffic.view', 'pbs.disks.view', 'pbs.subscription.view',
        'vmware.view', 'vmware.vm.view', 'vmware.vm.power', 'vmware.vm.snapshot',
        'vmware.vm.migrate', 'vmware.host.view', 'vmware.datastore.view', 'vmware.network.view',
    ],
    ROLE_VIEWER: [
        'vm.view', 'vm.console',
        'cluster.view',
        'node.view',
        'storage.view',
        'backup.view',
        'ha.view',
        'firewall.view',
        'pool.view',
        'replication.view',
        'pbs.view', 'pbs.datastore.view', 'pbs.jobs.view', 'pbs.tasks.view',
        'pbs.notifications.view', 'pbs.traffic.view', 'pbs.disks.view', 'pbs.subscription.view',
        'vmware.view', 'vmware.vm.view', 'vmware.host.view', 'vmware.datastore.view', 'vmware.network.view',
    ],
}
