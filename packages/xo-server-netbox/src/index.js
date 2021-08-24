"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exports.configurationSchema = void 0;

var _assert = _interopRequireDefault(require("assert"));

var _ipaddr = _interopRequireDefault(require("ipaddr.js"));

var _log = require("@xen-orchestra/log");

var _lodash = require("lodash");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const log = (0, _log.createLogger)('xo:netbox');
const CLUSTER_TYPE = 'XCP-ng Pool';
const CHUNK_SIZE = 100;
const NAME_MAX_LENGTH = 64;
const REQUEST_TIMEOUT = 120e3;
const M = 1024 ** 2;
const G = 1024 ** 3;
const {
  push
} = Array.prototype;

const diff = (newer, older) => {
  if (typeof newer !== 'object') {
    return newer === older ? undefined : newer;
  }

  newer = { ...newer
  };
  Object.keys(newer).forEach(key => {
    if (diff(newer[key], older[key]) === undefined) {
      delete newer[key];
    }
  });
  return (0, _lodash.isEmpty)(newer) ? undefined : newer;
};

const indexName = (name, index) => {
  const suffix = ` (${index})`;
  return name.slice(0, NAME_MAX_LENGTH - suffix.length) + suffix;
};

const onRequest = req => {
  req.setTimeout(REQUEST_TIMEOUT);
  req.on('timeout', req.abort);
};

class Netbox {
  #allowUnauthorized;
  #endpoint;
  #intervalToken;
  #loaded;
  #pools;
  #removeApiMethods;
  #ipTypes;
  #ignoredVmTags;
  #ignoredVmText;
  #netboxVrf;
  #netboxTenant;
  #syncInterval;
  #token;
  #xo;

  constructor({
    xo
  }) {
    this.#xo = xo;
  }

  configure(configuration) {
    var _configuration$allowU;

    this.#endpoint = (0, _lodash.trimEnd)(configuration.endpoint, '/');

    if (!/^https?:\/\//.test(this.#endpoint)) {
      this.#endpoint = 'http://' + this.#endpoint;
    }

    this.#allowUnauthorized = (_configuration$allowU = configuration.allowUnauthorized) !== null && _configuration$allowU !== void 0 ? _configuration$allowU : false;
    this.#token = configuration.token;
    this.#pools = configuration.pools;
    this.#ipTypes = configuration.ipTypes;
    this.#ignoredVmTags = configuration.ignoredVmTags;
    this.#ignoredVmText = configuration.ignoredVmText;
    this.#netboxVrf = configuration.netboxVrf;
    this.#netboxTenant = configuration.netboxTenant;
    this.#syncInterval = configuration.syncInterval && configuration.syncInterval * 60 * 60 * 1e3;


    if (this.#loaded) {
      clearInterval(this.#intervalToken);

      if (this.#syncInterval !== undefined) {
        this.#intervalToken = setInterval(this.#synchronize.bind(this), this.#syncInterval);
      }
    }
  }

  load() {
    const synchronize = ({
      pools
    }) => this.#synchronize(pools);

    synchronize.description = 'Synchronize XO pools with Netbox';
    synchronize.params = {
      pools: {
        type: 'array',
        optional: true,
        items: {
          type: 'string'
        }
      }
    };
    this.#removeApiMethods = this.#xo.addApiMethods({
      netbox: {
        synchronize
      }
    });

    if (this.#syncInterval !== undefined) {
      this.#intervalToken = setInterval(this.#synchronize.bind(this), this.#syncInterval);
    }

    this.#loaded = true;
  }

  unload() {
    this.#removeApiMethods();
    clearInterval(this.#intervalToken);
    this.#loaded = false;
  }

  async #makeRequest(path, method, data) {
    const dataDebug = Array.isArray(data) && data.length > 2 ? [...data.slice(0, 2), `and ${data.length - 2} others`] : data;
    log.debug(`${method} ${path}`, dataDebug);
    let url = this.#endpoint + '/api' + path;
    const options = {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Token ${this.#token}`
      },
      method,
      onRequest,
      rejectUnauthorized: !this.#allowUnauthorized
    };

    const httpRequest = async () => {
      try {
        const response = await this.#xo.httpRequest(url, options);
        const body = await response.readAll();

        if (body.length > 0) {
          return JSON.parse(body);
        }
      } catch (error) {
        error.data = {
          method,
          path,
          body: dataDebug
        };

        try {
          const body = await error.response.readAll();

          if (body.length > 0) {
            error.data.error = JSON.parse(body);
          }
        } catch {
          throw error;
        }

        throw error;
      }
    };

    let response = [];

    if (Array.isArray(data)) {
      let offset = 0;

      while (offset < data.length) {
        options.body = JSON.stringify(data.slice(offset, offset + CHUNK_SIZE));
        push.apply(response, await httpRequest());
        offset += CHUNK_SIZE;
      }
    } else {
      if (data !== undefined) {
        options.body = JSON.stringify(data);
      }

      response = await httpRequest();
    }

    if (method !== 'GET') {
      return response;
    }

    const {
      results
    } = response;

    while (response.next !== null) {
      const {
        pathname,
        search
      } = new URL(response.next);
      url = this.#endpoint + pathname + search;
      response = await httpRequest();
      push.apply(results, response.results);
    }

    return results;
  }

  async #synchronize(pools = this.#pools) {
    const xo = this.#xo;
    const ipTypes = this.#ipTypes;
    const ignoredVmTags = this.#ignoredVmTags;
    const ignoredVmText = this.#ignoredVmText;
    const netboxVrf = this.#netboxVrf;
    const netboxTenant = this.#netboxTenant;
    let primaryInterfaceName = 'eth0';	  
    let onmsMinionLocation = null;

    log.debug('synchronizing');
    const clusterTypes = await this.#makeRequest(`/virtualization/cluster-types/?name=${encodeURIComponent(CLUSTER_TYPE)}`, 'GET');

    if (clusterTypes.length > 1) {
      throw new Error('Found more than 1 "XCP-ng Pool" cluster type');
    }

    let clusterType;

    if (clusterTypes.length === 0) {
      clusterType = await this.#makeRequest('/virtualization/cluster-types/', 'POST', {
        name: CLUSTER_TYPE,
        slug: CLUSTER_TYPE.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
        description: 'Created by Xen Orchestra'
      });
    } else {
      clusterType = clusterTypes[0];
    }

    const clusters = (0, _lodash.keyBy)(await this.#makeRequest(`/virtualization/clusters/?type_id=${clusterType.id}`, 'GET'), 'custom_fields.uuid');
    const clustersToCreate = [];
    const clustersToUpdate = [];

    for (const poolId of pools) {
      const pool = xo.getObject(poolId);
      const cluster = clusters[pool.uuid];
      const updatedCluster = {
        name: pool.name_label.slice(0, NAME_MAX_LENGTH),
        type: clusterType.id,
        custom_fields: {
          uuid: pool.uuid
        }
      };

      if (cluster === undefined) {
        clustersToCreate.push(updatedCluster);
      } else {
        const patch = diff(updatedCluster, { ...cluster,
          type: cluster.type.id
        });

        if (patch !== undefined) {
          clustersToUpdate.push({ ...patch,
            id: cluster.id
          });
        }
      }
    }

// experimenting for getting the VIF and network/vlan	  
//log.info('all the things: ', xo.getObjects({ filter: object => object.type === 'PIF' }));
//log.info('zzz_other install media (1) VIF: ', xo.getObject('54cee6c8-9fbc-1de4-4194-f626dcfb54a7'));
//log.info('zzz_other install media (1) network: ', xo.getObject('2edcb618-01c6-1fc1-7225-5aee6f06f876'));
//log.info('zzz_other install media (1) network: ', xo.getObjects({ filter: object => object.id === 'cad6da45-2dfa-dd58-a82e-8c7b483ab11d' }));
//log.info('every object: ', xo.getObjects({ filter: object => object.type === 'PIF' && object.vlan === 705 }));
//log.info('container: ', xo.getObject('e1838cfc-35e1-4198-a20b-1d46db0d675b'));
//exit;

    Object.assign(clusters, (0, _lodash.keyBy)((0, _lodash.flatten)(await Promise.all(clustersToCreate.length === 0 ? [] : await this.#makeRequest('/virtualization/clusters/', 'POST', clustersToCreate), clustersToUpdate.length === 0 ? [] : await this.#makeRequest('/virtualization/clusters/', 'PATCH', clustersToUpdate))), 'custom_fields.uuid'));
    const vms = xo.getObjects({
      filter: object => object.type === 'VM' && pools.includes(object.$pool)
    });

    const oldNetboxVms = (0, _lodash.keyBy)((0, _lodash.flatten)(await Promise.all(pools.map(poolId => this.#makeRequest(`/virtualization/virtual-machines/?cluster_id=${clusters[poolId].id}`, 'GET')))), 'custom_fields.uuid');
    const netboxVms = {};
    const vifsByVm = {};
    const ipsByDeviceByVm = {};
    const vmsToCreate = [];
    const vmsToUpdate = [];
    const ignoredTags = [];
    let tenantId = null;	  

    // Get the Tenant ID from Netbox	  
    if (netboxTenant) {
      let tenant = {};
      tenant = (0, _lodash.keyBy)((0, _lodash.flatten)(await this.#makeRequest(`/tenancy/tenants/?name=${netboxTenant}`, 'GET')), 'id');

      for (const key of Object.keys(tenant)) {
        tenantId = Number(key);
        continue;
      }	    
    }

    // Get all the platforms
    const platforms = (0, _lodash.keyBy)((0, _lodash.flatten)(await this.#makeRequest(`/dcim/platforms/`, 'GET')), 'slug');
    
    vms: for (const vm of Object.values(vms)) {
      let platform = {};
      // Check to see if the VM has any tags which means it should be ignored from synchronising
      for (const vmTag of vm.tags) {
	if (ignoredVmTags !== undefined) {
          for (const tag of ignoredVmTags) {
  	    if (tag == vmTag) {
              // VM has a matching tag to ignore, move on to the next one
  	      continue vms;
	    }
          }
        }
      }

      // Check to see if the VM has any text in the name label which means it should be ignored from synchronising
      if (ignoredVmText !== undefined) {
        for (const ignoredText of ignoredVmText) {
	  const regex = new RegExp(ignoredText);

          if (regex.test(vm.name_label)) {
	    // Matching text in name label, move to next record
  	    continue vms;
	  }
        }
      }

      // Set the platform
      if (vm.os_version) {
        if (vm.os_version.distro !== undefined) {
	  platform = platforms[vm.os_version.distro + '-' + vm.os_version.major];
        } 
      }

      // Cycle through tags and look for identifiers
      // Netbox:Role: - sets the role
      let role = [];
      let roleName = null;
      let roleId = null;
      let tags = [];
      let tag = [];
      let tagName = null;
      let tagSlug = null;
      let tagId = null;
      let onmsMonitoring = false;
      const onmsCategories = [];

      // Retrieve a list of tags from netbox
      const netboxTags = (0, _lodash.keyBy)((0, _lodash.flatten)(await this.#makeRequest(`/extras/tags/`, 'GET')), 'name');

      tags: for (let vmTag of vm.tags) {
	// start checking for tags that begin with Netbox:
	if (/Netbox\:/.test(vmTag)) {
	  // Remove the Netbox prefix
	  vmTag = vmTag.replace('Netbox:', '');

          // now, let's look for a role
	  if (/Role\:/.test(vmTag)) {
	    roleName = vmTag.replace('Role:', '');
	    role = (0, _lodash.keyBy)((0, _lodash.flatten)(await this.#makeRequest(`/dcim/device-roles/?name=${roleName}`, 'GET')), 'name');
            roleId = role[roleName].id;

	    continue tags;
	  }

 	  // Check and see if a primary interface has been manually set
	  if (/PrimaryInterfaceName\:/.test(vmTag)) {
	    primaryInterfaceName = vmTag.replace('PrimaryInterfaceName:', '');
	    
	    continue tags;
	  }
	}

	if (/OpenNMS\:/.test(vmTag)) {
	  vmTag = vmTag.replace('OpenNMS:', '');

	  // is monitoring enabled?
	  if (/Monitoring\:/.test(vmTag)) {
	    if (/True/.test(vmTag.replace('Monitoring:', ''))) {
	      onmsMonitoring = true;
	    }

	    continue tags;
	  }

	  // Assign the minion location
	  if (/Location\:/.test(vmTag)) {
	    onmsMinionLocation = vmTag.replace('Location:', '');

	    continue tags;
	  }

	  // Assign the opennms categories
	  if (/Category\:/.test(vmTag)) {
	    onmsCategories.push(vmTag.replace('Category:', ''));

	    continue tags;
	  }
	}

	// Anything else, make it a tag in netbox
	if (netboxTags[vmTag]) {
	  tags.push(netboxTags[vmTag].id);
	} else {
	  ignoredTags.push(vmTag);
	}
	  
	  // now, let's look for OpenNMS tags
//	  if (/OpenNMS\:/.test(vmTag)) {
//	    tagSlug = tagName.toLowerCase()
//		      .replace(/^\s+|\s+$/g, ''); // trim		      
//		      .replace(/\:/g, '-')
//		      .replace(/[^a-z0-9 -]/g, '') // remove invalid chars
//                    .replace(/\s+/g, '-') // collapse whitespace and replace by -
//                    .replace(/-+/g, '-'); // collapse dashes
//	    tag = (0, _lodash.keyBy)((0, _lodash.flatten)(await this.#makeRequest(`/extras/tags/?name=${tagName}`, 'GET')), 'name');
//	    if (tag[tagName]) {
//  	      tags.push(tag[tagName].id);
//	    } else {
//              ignoredTags.push(tagName);
//	    }
//	  }
//	}
      }

      // retrieve the parent node for the vm
      const vmHost = xo.getObject(vm.$container);

      vifsByVm[vm.uuid] = vm.VIFs;
      const vmIpsByDevice = ipsByDeviceByVm[vm.uuid] = {};
      (0, _lodash.forEach)(vm.addresses, (address, key) => {
        const device = key.split('/')[0];

        if (vmIpsByDevice[device] === undefined) {
          vmIpsByDevice[device] = [];
        }

        vmIpsByDevice[device].push(address);
      });
      const oldNetboxVm = oldNetboxVms[vm.uuid];
      delete oldNetboxVms[vm.uuid];
      const cluster = clusters[vm.$pool];
      (0, _assert.default)(cluster !== undefined);
      const disk = Math.floor(vm.$VBDs.map(vbdId => xo.getObject(vbdId)).filter(vbd => !vbd.is_cd_drive).map(vbd => xo.getObject(vbd.VDI)).reduce((total, vdi) => total + vdi.size, 0) / G);
      const updatedVm = {
        name: vm.name_label.slice(0, NAME_MAX_LENGTH),
	platform: (platform !== undefined && platform.id !== undefined) ? platform.id : null,
        cluster: cluster.id,
        vcpus: vm.CPUs.number,
	tenant: tenantId,
	role: roleId,
        disk,
	tags: tags,
        memory: Math.floor(vm.memory.dynamic[1] / M),
        status: vm.power_state === 'Running' ? 'active' : 'offline',
        custom_fields: {
          uuid: vm.uuid,
	  onms_MonitoringStatus: onmsMonitoring,
	  onms_ParentNodeLabel: vmHost.name_label,
	  onms_MonitoringLocation: (onmsMinionLocation !== null) ? onmsMinionLocation : null,
	  onms_Category: (onmsCategories.length > 0) ? onmsCategories.join(",") : null
        }
      };

      if (oldNetboxVm === undefined) {
        vmsToCreate.push(updatedVm);
      } else {
        var _oldNetboxVm$status, _patch;

        let patch = diff(updatedVm, { ...oldNetboxVm,
          cluster: oldNetboxVm.cluster.id,
          status: (_oldNetboxVm$status = oldNetboxVm.status) === null || _oldNetboxVm$status === void 0 ? void 0 : _oldNetboxVm$status.value
        });

        if (((_patch = patch) === null || _patch === void 0 ? void 0 : _patch.name) !== undefined) {
          let match;

          if ((match = oldNetboxVm.name.match(/.* \((\d+)\)$/)) !== null) {
            if (indexName(patch.name, match[1]) === oldNetboxVm.name) {
              delete patch.name;

              if ((0, _lodash.isEmpty)(patch)) {
                patch = undefined;
              }
            }
          }
        }

        if (patch !== undefined) {
          vmsToUpdate.push({ ...patch,
            id: oldNetboxVm.id,
            $cluster: cluster.id
          });
        } else {
          netboxVms[vm.uuid] = oldNetboxVm;
        }
      }
    }

    vmsToCreate.forEach((vm, i) => {
      const name = vm.name;
      let nameIndex = 1;

      while ((0, _lodash.find)(netboxVms, netboxVm => netboxVm.cluster.id === vm.cluster && netboxVm.name === vm.name) !== undefined || (0, _lodash.find)(vmsToCreate, (vmToCreate, j) => vmToCreate.cluster === vm.cluster && vmToCreate.name === vm.name && i !== j) !== undefined) {
        if (nameIndex >= 1e3) {
          throw new Error(`Cannot deduplicate name of VM ${name}`);
        }

        vm.name = indexName(name, nameIndex++);
      }
    });

    vmsToUpdate.forEach((vm, i) => {
      const name = vm.name;

      if (name === undefined) {
        delete vm.$cluster;
        return;
      }

      let nameIndex = 1;

      while ((0, _lodash.find)(netboxVms, netboxVm => netboxVm.cluster.id === vm.$cluster && netboxVm.name === vm.name) !== undefined || (0, _lodash.find)(vmsToCreate, vmToCreate => vmToCreate.cluster === vm.$cluster && vmToCreate.name === vm.name) !== undefined || (0, _lodash.find)(vmsToUpdate, (vmToUpdate, j) => vmToUpdate.$cluster === vm.$cluster && vmToUpdate.name === vm.name && i !== j) !== undefined) {
        if (nameIndex >= 1e3) {
          throw new Error(`Cannot deduplicate name of VM ${name}`);
        }

        vm.name = indexName(name, nameIndex++);
      }

      delete vm.$cluster;
    });

    const vmsToDelete = Object.values(oldNetboxVms).map(vm => ({
      id: vm.id
    }));


    Object.assign(netboxVms, (0, _lodash.keyBy)((0, _lodash.flatten)((await Promise.all([vmsToDelete.length !== 0 && (await this.#makeRequest('/virtualization/virtual-machines/', 'DELETE', vmsToDelete)), vmsToCreate.length === 0 ? [] : await this.#makeRequest('/virtualization/virtual-machines/', 'POST', vmsToCreate), vmsToUpdate.length === 0 ? [] : await this.#makeRequest('/virtualization/virtual-machines/', 'PATCH', vmsToUpdate)])).slice(1)), 'custom_fields.uuid'));
    const oldInterfaces = (0, _lodash.mapValues)((0, _lodash.groupBy)((0, _lodash.flatten)(await Promise.all(pools.map(poolId => this.#makeRequest(`/virtualization/interfaces/?cluster_id=${clusters[poolId].id}`, 'GET')))), 'virtual_machine.id'), interfaces => (0, _lodash.keyBy)(interfaces, 'name'));
    const interfaces = {};
    const interfacesToCreateByVif = {};
    const interfacesToUpdateByVif = {};

    for (const [vmUuid, vifs] of Object.entries(vifsByVm)) {
      var _oldInterfaces$netbox;

      const netboxVmId = netboxVms[vmUuid].id;
      const vmInterfaces = (_oldInterfaces$netbox = oldInterfaces[netboxVmId]) !== null && _oldInterfaces$netbox !== void 0 ? _oldInterfaces$netbox : {};

      for (const vifId of vifs) {
        const vif = xo.getObject(vifId);
        const name = `eth${vif.device}`;
        const oldInterface = vmInterfaces[name];
        delete vmInterfaces[name];
        const updatedInterface = {
          name,
          mac_address: vif.MAC.toUpperCase(),
          virtual_machine: netboxVmId
        };

        if (oldInterface === undefined) {
          interfacesToCreateByVif[vif.uuid] = updatedInterface;
        } else {
          const patch = diff(updatedInterface, { ...oldInterface,
            virtual_machine: oldInterface.virtual_machine.id
          });

          if (patch !== undefined) {
            interfacesToUpdateByVif[vif.uuid] = { ...patch,
              id: oldInterface.id
            };
          } else {
            interfaces[vif.uuid] = oldInterface;
          }
        }
      }
    }

    // Log the fact that some tags got ignored
    const uniqueIgnoredTags = Array.from(new Set(ignoredTags));
    if (uniqueIgnoredTags.length > 0) {
      log.warn('Could not find tags for some. Ignoring them.', {
        tags: uniqueIgnoredTags
      });
    }


    const interfacesToDelete = (0, _lodash.flatten)(Object.values(oldInterfaces).map(oldInterfacesByName => Object.values(oldInterfacesByName).map(oldInterface => ({
      id: oldInterface.id
    }))));
    (await Promise.all([interfacesToDelete.length !== 0 && this.#makeRequest('/virtualization/interfaces/', 'DELETE', interfacesToDelete), (0, _lodash.isEmpty)(interfacesToCreateByVif) ? {} : this.#makeRequest('/virtualization/interfaces/', 'POST', Object.values(interfacesToCreateByVif)).then(interfaces => (0, _lodash.zipObject)(Object.keys(interfacesToCreateByVif), interfaces)), (0, _lodash.isEmpty)(interfacesToUpdateByVif) ? {} : this.#makeRequest('/virtualization/interfaces/', 'PATCH', Object.values(interfacesToUpdateByVif)).then(interfaces => (0, _lodash.zipObject)(Object.keys(interfacesToUpdateByVif), interfaces))])).slice(1).forEach(newInterfaces => Object.assign(interfaces, newInterfaces));
    const [oldNetboxIps, prefixes] = await Promise.all([this.#makeRequest('/ipam/ip-addresses/', 'GET').then(addresses => (0, _lodash.groupBy)(addresses.filter(address => address.assigned_object_type === 'virtualization.vminterface'), 'assigned_object_id')), this.#makeRequest(`/ipam/prefixes/?vrf_id=${netboxVrf}`, 'GET')]);
    const ipsToDelete = [];
    const ipsToCreate = [];
    const ignoredIps = [];

    for (const [vmUuid, vifs] of Object.entries(vifsByVm)) {
      const vmIpsByDevice = ipsByDeviceByVm[vmUuid];

      if (vmIpsByDevice === undefined) {
        continue;
      }

      for (const vifId of vifs) {
        var _oldNetboxIps$interfa;

        const vif = xo.getObject(vifId);
        const vifIps = vmIpsByDevice[vif.device];

        if (vifIps === undefined) {
          continue;
        }

        const interface_ = interfaces[vif.uuid];
        const interfaceOldIps = (_oldNetboxIps$interfa = oldNetboxIps[interface_.id]) !== null && _oldNetboxIps$interfa !== void 0 ? _oldNetboxIps$interfa : [];

        for (const ip of vifIps) {
	  if (/\s/.test(ip)) {
	    // whitespace in the IP found, split the record and then add them onto the end of the array for processing
	    // and move on to the next record
 	    var newIps = ip.split(" ");
	    vifIps.concat(newIps);
	    continue;
	  }

	  if (ip.length == 0) {
	    // IP length is zero but it's still trying to process it, move on to next in the list
	    continue;
	  }

          const parsedIp = _ipaddr.default.parse(ip);
          const ipKind = parsedIp.kind();

	  if (ipTypes == 'both') {
	    // Do nothing, carry on
	  } else if (ipTypes != ipKind) {
	    // Doesn't match IP Kind, move on to next IP in the list
	    continue;
	  }

          const ipCompactNotation = parsedIp.toString();
          const netboxIpIndex = interfaceOldIps.findIndex(netboxIp => _ipaddr.default.parse(netboxIp.address.split('/')[0]).toString() === ipCompactNotation);

          if (netboxIpIndex >= 0) {
            interfaceOldIps.splice(netboxIpIndex, 1);
          } else {
            const prefix = prefixes.find(({
              prefix
            }) => {
              const [range, bits] = prefix.split('/');

              const parsedRange = _ipaddr.default.parse(range);

              return parsedRange.kind() === ipKind && parsedIp.match(parsedRange, bits);
            });

            if (prefix === undefined) {
              ignoredIps.push(ip);
              continue;
            }

            ipsToCreate.push({
              address: `${ip}/${prefix.prefix.split('/')[1]}`,
              assigned_object_type: 'virtualization.vminterface',
              assigned_object_id: interface_.id,
	      vrf: netboxVrf
            });
          }
        }

        ipsToDelete.push(...interfaceOldIps.map(oldIp => ({
          id: oldIp.id
        })));
      }
    }

    if (ignoredIps.length > 0) {
      log.warn('Could not find prefix for some IPs: ignoring them.', {
        ips: ignoredIps
      });
    }

    // Assigning primary interfaces to VMs within Netbox
    log.info('Cycling through VMs to set/update primary interface in Netbox');
    const vmInterfacesToUpdate = [];

    for (const vm of Object.values(netboxVms)) {
      const vmInterfaces = await this.#makeRequest(`/virtualization/interfaces/?virtual_machine_id=${vm.id}`, 'GET');
      // (0, _lodash.keyBy)(await this.#makeRequest(`/virtualization/clusters/?type_id=${clusterType.id}`, 'GET'), 'custom_fields.uuid');

      for (const vmInt of Object.values(vmInterfaces)) {
	// check to see whether the interface name matches the default and that the interface is enabled
        if (vmInt.name == primaryInterfaceName && vmInt.enabled == true) {
          const vmIps = await this.#makeRequest(`/ipam/ip-addresses/?vminterface_id=${vmInt.id}`, 'GET');

          vmInterfacesToUpdate.push({
	    id: vm.id,
	    primary_ip4: vmIps.length > 0 ? vmIps[0].id : null // We're only going to use the first IP found in that search, regardless of how many are assigned (for now)
	  });
	}
      }
    }

    log.info('Updating primary interfaces on virtual machines');
    await Promise.all([vmInterfacesToUpdate.length !== 0 && await this.#makeRequest('/virtualization/virtual-machines/', 'PATCH', vmInterfacesToUpdate)]);


    await Promise.all([ipsToDelete.length !== 0 && this.#makeRequest('/ipam/ip-addresses/', 'DELETE', ipsToDelete), ipsToCreate.length !== 0 && this.#makeRequest('/ipam/ip-addresses/', 'POST', ipsToCreate)]);
    log.debug('synchronized');
  }

  async test() {
    const randomSuffix = Math.random().toString(36).slice(2);
    const name = '[TMP] Xen Orchestra Netbox plugin test - ' + randomSuffix;
    await this.#makeRequest('/virtualization/cluster-types/', 'POST', {
      name,
      slug: 'xo-test-' + randomSuffix,
      description: "This type has been created by Xen Orchestra's Netbox plugin test. If it hasn't been properly deleted, you may delete it manually."
    });
    const clusterTypes = await this.#makeRequest(`/virtualization/cluster-types/?name=${encodeURIComponent(name)}`, 'GET');

    if (clusterTypes.length !== 1) {
      throw new Error('Could not properly write and read Netbox');
    }

    await this.#makeRequest('/virtualization/cluster-types/', 'DELETE', [{
      id: clusterTypes[0].id
    }]);
  }

}

const configurationSchema = ({
  xo: {
    apiMethods
  }
}) => ({
  description: 'Synchronize pools managed by Xen Orchestra with Netbox. Configuration steps: https://xen-orchestra.com/docs/advanced.html#netbox.',
  type: 'object',
  properties: {
    endpoint: {
      type: 'string',
      title: 'Endpoint',
      description: 'Netbox URI'
    },
    allowUnauthorized: {
      type: 'boolean',
      title: 'Unauthorized certificates',
      description: 'Enable this if your Netbox instance uses a self-signed SSL certificate'
    },
    token: {
      type: 'string',
      title: 'Token',
      description: 'Generate a token with write permissions from your Netbox interface'
    },
    pools: {
      type: 'array',
      title: 'Pools',
      description: 'Pools to synchronize with Netbox',
      items: {
        type: 'string',
        $type: 'pool'
      }
    },
    ipTypes: {
      title: 'IP Types',
      default: 'ipv4',
      enum: ['ipv4', 'ipv6', 'both'],
      enumNames: ['IPv4', 'IPv6', 'Both (IPv4 and IPv6)'],
      description: 'Choose whether to synchronise IPv4, IPv6 or Both types of IPs'
    },
    ignoredVmTags: {
      type: 'array',
      title: 'Ignored VM tags',
      description: 'list of VM tags to never synchronise specific VMs',
      items: {
        type: 'string',
        $type: 'Tag'
      }
    },
    ignoredVmText: {
      type: 'array',
      title: 'Ignored VM text',
      description: 'Text in the name of the VM which indicates it should not be synchronised',
      items: {
        type: 'string'
      }
    },
    netboxVrf: {
      type: 'number',
      title: 'Netbox VRF ID',
      description: 'The VRF ID in Netbox for the network this instance is a part of'
    },
    netboxTenant: {
      type: 'string',
      title: 'Netbox Tenant Name',
      description: 'The tenant name in Netbox that these VMs should be attached to'
    },
    syncInterval: {
      type: 'number',
      title: 'Interval',
      description: 'Synchronization interval in hours - leave empty to disable auto-sync'
    },
  },

  required: ['endpoint', 'token', 'pools', 'ipTypes']
});

exports.configurationSchema = configurationSchema;

var _default = opts => new Netbox(opts);

exports.default = _default;
//# sourceMappingURL=index.js.map
