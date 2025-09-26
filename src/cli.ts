#!/usr/bin/env node

import { MeshCorePacketDecoder } from './decoder/packet-decoder';
import { PayloadType, DeviceRole } from './types/enums';
import { getRouteTypeName, getPayloadTypeName, getDeviceRoleName } from './utils/enum-names';
import { AdvertPayload, GroupTextPayload, TracePayload } from './types/payloads';
import { program } from 'commander';
import chalk from 'chalk';
import * as packageJson from '../package.json';

program
  .name('meshcore-decoder')
  .description('CLI tool for decoding MeshCore packets')
  .version(packageJson.version)
  .argument('<hex>', 'Hex string of the packet to decode')
  .option('-k, --key <keys...>', 'Channel secret keys for decryption (hex)')
  .option('-j, --json', 'Output as JSON instead of formatted text')
  .option('-s, --structure', 'Show detailed packet structure analysis')
  .action(async (hex: string, options: any) => {
    try {
      // Clean up hex input
      const cleanHex = hex.replace(/\s+/g, '').replace(/^0x/i, '');
      
      // Create key store if keys provided
      let keyStore;
      if (options.key && options.key.length > 0) {
        keyStore = MeshCorePacketDecoder.createKeyStore({
          channelSecrets: options.key
        });
      }
      
      // Decode packet with signature verification
      const packet = await MeshCorePacketDecoder.decodeWithVerification(cleanHex, { keyStore });
      
      if (options.json) {
        // JSON output
        if (options.structure) {
          const structure = await MeshCorePacketDecoder.analyzeStructureWithVerification(cleanHex, { keyStore });
          console.log(JSON.stringify({ packet, structure }, null, 2));
        } else {
          console.log(JSON.stringify(packet, null, 2));
        }
      } else {
        // Formatted output
        console.log(chalk.cyan('=== MeshCore Packet Analysis ===\n'));
        
        if (!packet.isValid) {
          console.log(chalk.red('❌ Invalid Packet'));
          if (packet.errors) {
            packet.errors.forEach(error => console.log(chalk.red(`   ${error}`)));
          }
        } else {
          console.log(chalk.green('✅ Valid Packet'));
        }
        
        console.log(`${chalk.bold('Message Hash:')} ${packet.messageHash}`);
        console.log(`${chalk.bold('Route Type:')} ${getRouteTypeName(packet.routeType)}`);
        console.log(`${chalk.bold('Payload Type:')} ${getPayloadTypeName(packet.payloadType)}`);
        console.log(`${chalk.bold('Total Bytes:')} ${packet.totalBytes}`);
        
        if (packet.path && packet.path.length > 0) {
          console.log(`${chalk.bold('Path:')} ${packet.path.join(' → ')}`);
        }
        
        // Show payload details (even for invalid packets)
        if (packet.payload.decoded) {
          console.log(chalk.cyan('\n=== Payload Details ==='));
          showPayloadDetails(packet.payload.decoded);
        }
        
        // Exit with error code if packet is invalid
        if (!packet.isValid) {
          process.exit(1);
        }
        
        // Show structure if requested
        if (options.structure) {
          const structure = await MeshCorePacketDecoder.analyzeStructureWithVerification(cleanHex, { keyStore });
          console.log(chalk.cyan('\n=== Packet Structure ==='));
          
          console.log(chalk.yellow('\nMain Segments:'));
          structure.segments.forEach((seg, i) => {
            console.log(`${i + 1}. ${chalk.bold(seg.name)} (bytes ${seg.startByte}-${seg.endByte}): ${seg.value}`);
            if (seg.description) {
              console.log(`   ${chalk.dim(seg.description)}`);
            }
          });
          
          if (structure.payload.segments.length > 0) {
            console.log(chalk.yellow('\nPayload Segments:'));
            structure.payload.segments.forEach((seg, i) => {
              console.log(`${i + 1}. ${chalk.bold(seg.name)} (bytes ${seg.startByte}-${seg.endByte}): ${seg.value}`);
              console.log(`   ${chalk.dim(seg.description)}`);
            });
          }
        }
      }
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

function showPayloadDetails(payload: any): void {
  switch (payload.type) {
    case PayloadType.Advert:
      const advert = payload as AdvertPayload;
      console.log(`${chalk.bold('Device Role:')} ${getDeviceRoleName(advert.appData.deviceRole)}`);
      if (advert.appData.name) {
        console.log(`${chalk.bold('Device Name:')} ${advert.appData.name}`);
      }
      if (advert.appData.location) {
        console.log(`${chalk.bold('Location:')} ${advert.appData.location.latitude}, ${advert.appData.location.longitude}`);
      }
      console.log(`${chalk.bold('Timestamp:')} ${new Date(advert.timestamp * 1000).toISOString()}`);
      
      // Show signature verification status
      if (advert.signatureValid !== undefined) {
        if (advert.signatureValid) {
          console.log(`${chalk.bold('Signature:')} ${chalk.green('✅ Valid Ed25519 signature')}`);
        } else {
          console.log(`${chalk.bold('Signature:')} ${chalk.red('❌ Invalid Ed25519 signature')}`);
          if (advert.signatureError) {
            console.log(`${chalk.bold('Error:')} ${chalk.red(advert.signatureError)}`);
          }
        }
      } else {
        console.log(`${chalk.bold('Signature:')} ${chalk.yellow('⚠️ Not verified (use async verification)')}`);
      }
      break;
      
    case PayloadType.GroupText:
      const groupText = payload as GroupTextPayload;
      console.log(`${chalk.bold('Channel Hash:')} ${groupText.channelHash}`);
      if (groupText.decrypted) {
        console.log(chalk.green('🔓 Decrypted Message:'));
        if (groupText.decrypted.sender) {
          console.log(`${chalk.bold('Sender:')} ${groupText.decrypted.sender}`);
        }
        console.log(`${chalk.bold('Message:')} ${groupText.decrypted.message}`);
        console.log(`${chalk.bold('Timestamp:')} ${new Date(groupText.decrypted.timestamp * 1000).toISOString()}`);
      } else {
        console.log(chalk.yellow('🔒 Encrypted (no key available)'));
        console.log(`${chalk.bold('Ciphertext:')} ${groupText.ciphertext.substring(0, 32)}...`);
      }
      break;
      
    case PayloadType.Trace:
      const trace = payload as TracePayload;
      console.log(`${chalk.bold('Trace Tag:')} ${trace.traceTag}`);
      console.log(`${chalk.bold('Auth Code:')} ${trace.authCode}`);
      if (trace.snrValues && trace.snrValues.length > 0) {
        console.log(`${chalk.bold('SNR Values:')} ${trace.snrValues.map(snr => `${snr.toFixed(1)}dB`).join(', ')}`);
      }
      break;
      
    default:
      console.log(`${chalk.bold('Type:')} ${getPayloadTypeName(payload.type)}`);
      console.log(`${chalk.bold('Valid:')} ${payload.isValid ? '✅' : '❌'}`);
  }
}

program.parse();
