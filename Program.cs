using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.IO;
using AsmResolver.PE.DotNet.Builder;
using AsmResolver.PE.DotNet.Cil;
namespace SecureByteJIT_Unpacker
{
    internal class Program
    {
        private static List<Tuple<string, byte[]>> TokenAndBody = new List<Tuple<string, byte[]>>();
        private static ModuleDefinition moduleDefinition;
        private static byte[] JITData;
        static void Main(string[] args)
        {
            moduleDefinition = ModuleDefinition.FromFile(args[0]);
            FindJITDataResource();    
            DecryptJITDataAndRestoreMethods();
           
            var method_count = TokenAndBody.Select(tuple => tuple.Item1).Count();
            Console.WriteLine($"Decrypted {method_count} methods!");

            var imageBuilder = new ManagedPEImageBuilder();
            var result = imageBuilder.CreateImage(moduleDefinition);
            var image = result.ConstructedImage;
            var fileBuilder = new ManagedPEFileBuilder();
            var file = fileBuilder.CreateFile(image);
            string output = args[0].Insert(args[0].Length - 4, "_decrypted");
            file.Write(output);
            Console.ReadKey();
        }

        [Obsolete]
        private static void DecryptJITDataAndRestoreMethods()
        {
            BinaryReader binaryReader = new BinaryReader(new MemoryStream(JITData));
           
            var num = binaryReader.ReadInt32();
            for (int i = 0; i < num; i++)
            {
                var methods = moduleDefinition.LookupMember(binaryReader.ReadInt32());
                var text = binaryReader.ReadString();
                var decryptedData = Convert.FromBase64String(text);
                TokenAndBody.Add(Tuple.Create(methods.MetadataToken.ToString(), decryptedData));
            }

            foreach (var t in moduleDefinition.GetAllTypes())
            {
                foreach (var m in t.Methods)
                {
                    if (!m.HasMethodBody) continue;
                    if (!TokenAndBody.Select(tuple => tuple.Item1).Contains(m.MetadataToken.ToString())) continue;    
                    var reader = ByteArrayDataSource.CreateReader(TokenAndBody.FirstOrDefault(tuple => tuple.Item1 == m.MetadataToken.ToString()).Item2);
                    var dissassembler = new CilDisassembler(in reader,
                            new PhysicalCilOperandResolver(moduleDefinition, m.CilMethodBody));
                    var instrs = dissassembler.ReadInstructions();
                    m.CilMethodBody.Instructions.Clear();
                    m.CilMethodBody.Instructions.AddRange(instrs);      
                }
            }    
        }

        private static void FindJITDataResource()
        {
            var cctor = moduleDefinition.GetModuleConstructor().CilMethodBody.Instructions;
            for (int i = 0; i < cctor.Count; i++)
            {
                if (cctor[i].OpCode == CilOpCodes.Ldstr && cctor[i + 1].OpCode == CilOpCodes.Call)
                {
                    var jitExecuteMdProxy = cctor[i + 1].Operand as MethodDefinition;
                    Console.WriteLine($"JIT Execute Proxy Method: {jitExecuteMdProxy}");
                    var instrs = jitExecuteMdProxy.CilMethodBody.Instructions;
                    for (int i2 = 0; i2 < instrs.Count; i2++)
                    {
                        if (instrs[i2].OpCode == CilOpCodes.Call)
                        {
                            var jitExecuteMd = instrs[i2].Operand as MethodDefinition;
                            Console.WriteLine($"JIT Execute Method: {jitExecuteMd}");
                            var instrs2 = jitExecuteMd.CilMethodBody.Instructions;
                            for (int i3 = 0; i3 < instrs2.Count; i3++)
                            {
                                if (instrs2[i3].IsLdloc() && instrs2[i3 + 1].OpCode == CilOpCodes.Callvirt && instrs2[i3 + 2].OpCode == CilOpCodes.Ldstr)
                                {
                                    var resourceName = instrs2[i3 + 2].Operand as string;
                                    Console.WriteLine($"JIT Data Resource Name: {resourceName}");
                                    var resource = moduleDefinition.Resources.First(q => q.Name == resourceName);
                                    JITData = resource.GetData();
                                }
                            }

                        }
                    }
                    break;
                }
            }          
        }
    }
}
