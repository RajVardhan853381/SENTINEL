# src/sentinels/schemas/manifest.py
from pydantic import BaseModel, Field
from typing import List, Dict

class FileInfo(BaseModel):
    """
    Represents a single file in the repository.
    """
    path: str = Field(..., description="The relative path of the file from the repo root.")
    size_bytes: int = Field(..., description="Size of the file in bytes.")
    language: str = Field(..., description="Detected programming language (e.g., 'Python', 'Terraform', 'JSON').")

class DirectoryCluster(BaseModel):
    """
    Summarizes a directory cluster for large repositories to prevent prompt context blowout.
    """
    directory: str = Field(..., description="The relative directory path (e.g., 'src/api', 'infra/terraform').")
    file_count: int = Field(..., description="Number of source files contained in this directory cluster.")
    languages: List[str] = Field(default_factory=list, description="Languages present in this cluster.")
    sample_files: List[str] = Field(default_factory=list, description="A representative sample of filenames in this cluster.")

class RepoManifest(BaseModel):
    """
    A structured map of the repository.
    This is passed to the Manager Agent so it can plan the scan without reading raw code.
    """
    repo_url: str = Field(..., description="The URL of the cloned repository.")
    local_path: str = Field(..., description="The local sandbox path where the repo was cloned.")
    sandbox_dir: str | None = Field(default=None, description="The root temporary sandbox directory containing the clone.")
    branch: str = Field(default="main", description="The branch that was scanned.")
    
    total_files: int = Field(..., description="Total number of source files detected (ignoring .git, node_modules, etc.).")
    
    languages: List[str] = Field(
        default_factory=list, 
        description="Unique list of programming languages detected in the repo."
    )
    
    frameworks: List[str] = Field(
        default_factory=list, 
        description="Detected frameworks (e.g., 'Flask', 'React', 'Terraform')."
    )
    
    files: List[FileInfo] = Field(
        default_factory=list, 
        description="The filtered list of relevant source files to be audited."
    )

    is_windowed: bool = Field(
        default=False,
        description="True if the repository is large (>250 files) and file listing has been clustered."
    )

    directory_clusters: List[DirectoryCluster] = Field(
        default_factory=list,
        description="Logical directory clusters for efficient agentic delegation without context exhaustion."
    )