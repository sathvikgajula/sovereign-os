import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

interface Node extends d3.SimulationNodeDatum {
    id: string;
    trust: number;
    did: string;
}

interface Link extends d3.SimulationLinkDatum<Node> {
    source: string;
    target: string;
}

interface MeshGraphProps {
    peers: { peer_did: string; alpha: number; beta: number }[];
}

export const MeshGraph: React.FC<MeshGraphProps> = ({ peers }) => {
    const svgRef = useRef<SVGSVGElement>(null);

    useEffect(() => {
        if (!svgRef.current || peers.length === 0) return;

        const width = svgRef.current.clientWidth;
        const height = svgRef.current.clientHeight;

        const nodes: Node[] = peers.map(p => {
            const trust = p.alpha / (p.alpha + p.beta);
            return {
                id: p.peer_did,
                did: p.peer_did,
                trust,
                x: width / 2 + (Math.random() - 0.5) * 100,
                y: height / 2 + (Math.random() - 0.5) * 100,
            };
        });

        // Hub node (Self)
        nodes.push({ id: 'me', did: 'me', trust: 1.0, x: width / 2, y: height / 2 });

        const links: Link[] = peers.map(p => ({
            source: 'me',
            target: p.peer_did,
        }));

        const svg = d3.select(svgRef.current);
        svg.selectAll("*").remove();

        const simulation = d3.forceSimulation<Node>(nodes)
            .force("link", d3.forceLink<Node, Link>(links).id(d => d.id).distance((d: any) => {
                // d.target is the Node object here after initialization
                return (1 - d.target.trust) * 300 + 50;
            }))
            .force("charge", d3.forceManyBody().strength(-100))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(30));

        const link = svg.append("g")
            .selectAll("line")
            .data(links)
            .join("line")
            .attr("stroke", "#333")
            .attr("stroke-opacity", 0.2) // Hydra tunnels low opacity
            .attr("stroke-width", 1);

        const node = svg.append("g")
            .selectAll("circle")
            .data(nodes)
            .join("circle")
            .attr("r", d => d.id === 'me' ? 12 : 8)
            .attr("fill", d => {
                if (d.trust > 0.9) return "var(--color-cyber)";
                if (d.trust > 0.4) return "var(--color-amber)";
                return "var(--color-crimson)";
            })
            .attr("filter", d => {
                if (d.trust > 0.9) return "drop-shadow(0 0 12px var(--color-cyber))";
                if (d.trust > 0.4) return "drop-shadow(0 0 6px var(--color-amber))";
                return "drop-shadow(0 0 8px var(--color-crimson))";
            })
            .attr("class", d => {
                if (d.trust > 0.9) return "animate-pulse cursor-pointer";
                if (d.trust < 0.4) return "animate-flicker";
                return "transition-all";
            })
            .call(d3.drag<SVGCircleElement, Node>()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended) as any);

        node.append("title").text(d => `${d.did}\nE[R]: ${d.trust.toFixed(4)}`);

        simulation.on("tick", () => {
            link
                .attr("x1", (d: any) => d.source.x)
                .attr("y1", (d: any) => d.source.y)
                .attr("x2", (d: any) => d.target.x)
                .attr("y2", (d: any) => d.target.y);

            node
                .attr("cx", d => d.x!)
                .attr("cy", d => d.y!);
        });

        function dragstarted(event: any, d: any) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event: any, d: any) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event: any, d: any) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        return () => { simulation.stop(); };
    }, [peers]);

    return (
        <svg ref={svgRef} className="w-full h-full bg-black/20 rounded-xl cursor-crosshair" />
    );
};
