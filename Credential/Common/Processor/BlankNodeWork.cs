using System.Text;
using VDS.RDF;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Processor;

/// <summary>
/// Scores the search URDNA2015 will do and refuses datasets that would take it
/// factorial time (port of Go blankNodeWork / normalizeDataset). dotNetRDF has no
/// limit of its own and the search cannot be stopped from outside.
/// </summary>
public static class BlankNodeWork
{
    /// <summary>Admits every ordinary document (score 0, or 8 per pair of equal proofs, or a list of 102 equal values); refuses a clique of 4 (46656).</summary>
    public const int MaxBlankNodeWork = 20000;

    /// <summary>The one call into RDFC-1.0: throws <see cref="BlankNodeWorkException"/> above the cap.</summary>
    public static RdfCanonicalizer.CanonicalizedRdfDataset Normalize(ITripleStore store)
    {
        if (Score(store) > MaxBlankNodeWork)
            throw new BlankNodeWorkException("normalize: too many interchangeable blank nodes");
        return new RdfCanonicalizer().Canonicalize(store);
    }

    // A blank node whose quads, with blank nodes masked, match no other node's is
    // labelled at once and costs nothing. The rest are interchangeable: Hash N-Degree
    // Quads tries every ordering of each list of nodes related to one the same way.
    // A group scores orderings x size x edges to blank nodes.
    public static long Score(ITripleStore store)
    {
        var lines = new Dictionary<string, List<string>>();
        var related = new Dictionary<string, List<(string How, string Id)>>();
        foreach (var graph in store.Graphs)
        {
            INode? g = graph.Name;
            foreach (var t in graph.Triples)
            {
                var nodes = new INode?[] { t.Subject, t.Object, g };
                foreach (var n in nodes)
                {
                    if (n is not IBlankNode bn) continue;
                    var id = bn.InternalID;
                    if (!lines.TryGetValue(id, out var l)) lines[id] = l = new();
                    l.Add($"{Masked(nodes[0], id)} {t.Predicate} {Masked(nodes[1], id)} {Masked(nodes[2], id)}");
                    for (var i = 0; i < nodes.Length; i++)
                    {
                        if (nodes[i] is IBlankNode other && other.InternalID != id)
                        {
                            // Hash Related Blank Node leaves the predicate out for a graph name.
                            var how = i < 2 ? i + t.Predicate.ToString() : "g";
                            if (!related.TryGetValue(id, out var r)) related[id] = r = new();
                            r.Add((how, other.InternalID));
                        }
                    }
                }
            }
        }

        // Signatures are interned because a list key below copies one per relation.
        var signatures = new Dictionary<string, int>(lines.Count);
        var interned = new Dictionary<string, int>(lines.Count);
        var sharing = new Dictionary<int, int>(lines.Count);
        foreach (var (id, l) in lines)
        {
            l.Sort(StringComparer.Ordinal);
            var sig = string.Join("\n", l);
            if (!interned.TryGetValue(sig, out var n)) interned[sig] = n = interned.Count;
            signatures[id] = n;
            sharing[n] = sharing.GetValueOrDefault(n) + 1;
        }
        bool Interchangeable(string id) => sharing[signatures[id]] > 1;

        long work = 0;
        var seen = new HashSet<string>();
        foreach (var start in lines.Keys)
        {
            if (seen.Contains(start) || !Interchangeable(start)) continue;
            seen.Add(start);
            var group = new List<string> { start };
            long orderings = 1;
            long edges = 0;
            for (var i = 0; i < group.Count; i++)
            {
                var rels = related.GetValueOrDefault(group[i]) ?? new();
                edges += rels.Count;
                // Lists can repeat a node; the distinct orderings are the running multinomial of each list.
                var counts = new Dictionary<string, long>();
                foreach (var (how, rid) in rels)
                {
                    var list = how + "\0" + signatures[rid];
                    var each = list + "\0" + rid;
                    counts[list] = counts.GetValueOrDefault(list) + 1;
                    counts[each] = counts.GetValueOrDefault(each) + 1;
                    orderings = orderings * counts[list] / counts[each];
                    if (orderings > MaxBlankNodeWork) return orderings;
                    if (!seen.Contains(rid) && Interchangeable(rid))
                    {
                        seen.Add(rid);
                        group.Add(rid);
                    }
                }
            }
            var search = orderings * group.Count;
            if (search > 1)
            {
                work += search * edges;
                if (work > MaxBlankNodeWork) return work;
            }
        }
        return work;
    }

    // Hash First Degree Quads rule: the node under test reads as _:a, every other blank as _:z.
    private static string Masked(INode? n, string id) => n switch
    {
        null => "",
        IBlankNode b => b.InternalID == id ? "_:a" : "_:z",
        _ => n.ToString() ?? "",
    };
}
