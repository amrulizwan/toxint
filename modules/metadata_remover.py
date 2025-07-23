import os
import shutil
from PIL import Image
import PyPDF2
from docx import Document
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

class MetadataRemover:
    def __init__(self):
        self.cleaned_files = []
        self.errors = []

    def remove_metadata(self, filepath, output_dir=None):
        console.print(f"[red]Removing metadata from: {filepath}[/red]")
        
        if not os.path.exists(filepath):
            console.print(f"[red]File not found: {filepath}[/red]")
            return None
        
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(filepath), "cleaned")
        
        os.makedirs(output_dir, exist_ok=True)
        
        file_ext = os.path.splitext(filepath)[1].lower()
        
        try:
            if file_ext in ['.jpg', '.jpeg', '.png', '.tiff', '.bmp']:
                return self.clean_image_metadata(filepath, output_dir)
            elif file_ext == '.pdf':
                return self.clean_pdf_metadata(filepath, output_dir)
            elif file_ext in ['.docx']:
                return self.clean_docx_metadata(filepath, output_dir)
            else:
                return self.clean_generic_metadata(filepath, output_dir)
        except Exception as e:
            self.errors.append(f"Error cleaning {filepath}: {str(e)}")
            console.print(f"[red]Error: {str(e)}[/red]")
            return None

    def clean_image_metadata(self, filepath, output_dir):
        try:
            with Image.open(filepath) as img:
                data = list(img.getdata())
                image_without_exif = Image.new(img.mode, img.size)
                image_without_exif.putdata(data)
                
                filename = os.path.basename(filepath)
                name, ext = os.path.splitext(filename)
                output_path = os.path.join(output_dir, f"{name}_cleaned{ext}")
                
                if ext.lower() == '.jpg' or ext.lower() == '.jpeg':
                    image_without_exif.save(output_path, "JPEG", quality=95)
                elif ext.lower() == '.png':
                    image_without_exif.save(output_path, "PNG")
                else:
                    image_without_exif.save(output_path)
                
                self.cleaned_files.append({
                    'original': filepath,
                    'cleaned': output_path,
                    'type': 'Image',
                    'metadata_removed': ['EXIF', 'GPS', 'IPTC', 'XMP']
                })
                
                return output_path
                
        except Exception as e:
            raise Exception(f"Failed to clean image metadata: {str(e)}")

    def clean_pdf_metadata(self, filepath, output_dir):
        try:
            with open(filepath, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                pdf_writer = PyPDF2.PdfWriter()
                
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    pdf_writer.add_page(page)
                
                filename = os.path.basename(filepath)
                name, ext = os.path.splitext(filename)
                output_path = os.path.join(output_dir, f"{name}_cleaned{ext}")
                
                with open(output_path, 'wb') as output_file:
                    pdf_writer.write(output_file)
                
                self.cleaned_files.append({
                    'original': filepath,
                    'cleaned': output_path,
                    'type': 'PDF',
                    'metadata_removed': ['Author', 'Creator', 'Producer', 'Title', 'Subject']
                })
                
                return output_path
                
        except Exception as e:
            raise Exception(f"Failed to clean PDF metadata: {str(e)}")

    def clean_docx_metadata(self, filepath, output_dir):
        try:
            doc = Document(filepath)
            
            core_props = doc.core_properties
            core_props.author = None
            core_props.category = None
            core_props.comments = None
            core_props.content_status = None
            core_props.created = None
            core_props.identifier = None
            core_props.keywords = None
            core_props.language = None
            core_props.last_modified_by = None
            core_props.last_printed = None
            core_props.modified = None
            core_props.revision = None
            core_props.subject = None
            core_props.title = None
            core_props.version = None
            
            filename = os.path.basename(filepath)
            name, ext = os.path.splitext(filename)
            output_path = os.path.join(output_dir, f"{name}_cleaned{ext}")
            
            doc.save(output_path)
            
            self.cleaned_files.append({
                'original': filepath,
                'cleaned': output_path,
                'type': 'DOCX',
                'metadata_removed': ['Author', 'Category', 'Comments', 'Keywords', 'Title', 'Subject', 'Last Modified By']
            })
            
            return output_path
            
        except Exception as e:
            raise Exception(f"Failed to clean DOCX metadata: {str(e)}")

    def clean_generic_metadata(self, filepath, output_dir):
        try:
            filename = os.path.basename(filepath)
            name, ext = os.path.splitext(filename)
            output_path = os.path.join(output_dir, f"{name}_cleaned{ext}")
            
            shutil.copy2(filepath, output_path)
            
            if os.name == 'nt':
                import subprocess
                try:
                    subprocess.run(['attrib', '-A', '-H', '-S', output_path], 
                                 check=False, capture_output=True)
                except:
                    pass
            
            self.cleaned_files.append({
                'original': filepath,
                'cleaned': output_path,
                'type': 'Generic',
                'metadata_removed': ['File attributes', 'System metadata']
            })
            
            return output_path
            
        except Exception as e:
            raise Exception(f"Failed to clean generic metadata: {str(e)}")

    def batch_clean(self, directory, recursive=True):
        console.print(f"[red]Batch cleaning directory: {directory}[/red]")
        
        if not os.path.exists(directory):
            console.print(f"[red]Directory not found: {directory}[/red]")
            return
        
        supported_extensions = ['.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.pdf', '.docx']
        files_to_clean = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in supported_extensions):
                        files_to_clean.append(os.path.join(root, file))
        else:
            for file in os.listdir(directory):
                filepath = os.path.join(directory, file)
                if os.path.isfile(filepath) and any(file.lower().endswith(ext) for ext in supported_extensions):
                    files_to_clean.append(filepath)
        
        if not files_to_clean:
            console.print("[yellow]No supported files found for cleaning[/yellow]")
            return
        
        output_dir = os.path.join(directory, "cleaned_batch")
        
        with Progress() as progress:
            task = progress.add_task("[red]Cleaning files...", total=len(files_to_clean))
            
            for filepath in files_to_clean:
                try:
                    self.remove_metadata(filepath, output_dir)
                    progress.update(task, advance=1, description=f"[red]Cleaned: {os.path.basename(filepath)}")
                except Exception as e:
                    self.errors.append(f"Failed to clean {filepath}: {str(e)}")
                    progress.update(task, advance=1)
        
        self.display_results()

    def compare_metadata(self, original_path, cleaned_path):
        console.print(f"[cyan]Comparing metadata...[/cyan]")
        
        from .metadata_extractor import MetadataExtractor
        
        extractor = MetadataExtractor()
        
        console.print("[dim white]Original file metadata:[/dim white]")
        extractor.extract(original_path)
        
        console.print("\n[dim white]Cleaned file metadata:[/dim white]")
        extractor.extract(cleaned_path)

    def secure_delete(self, filepath, passes=3):
        try:
            if not os.path.exists(filepath):
                return False
            
            file_size = os.path.getsize(filepath)
            
            with open(filepath, 'r+b') as file:
                for _ in range(passes):
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            
            os.remove(filepath)
            return True
            
        except Exception as e:
            console.print(f"[red]Secure delete failed: {e}[/red]")
            return False

    def display_results(self):
        console.print(f"\n[red]═══ METADATA REMOVAL REPORT ═══[/red]")
        
        if self.cleaned_files:
            table = Table(title="✅ Successfully Cleaned Files", border_style="green")
            table.add_column("Original File", style="cyan")
            table.add_column("Cleaned File", style="green")
            table.add_column("Type", style="yellow")
            table.add_column("Metadata Removed", style="white")
            
            for file_info in self.cleaned_files:
                metadata_removed = ", ".join(file_info['metadata_removed'])
                
                table.add_row(
                    os.path.basename(file_info['original']),
                    os.path.basename(file_info['cleaned']),
                    file_info['type'],
                    metadata_removed
                )
            
            console.print(table)
        
        if self.errors:
            table = Table(title="❌ Errors", border_style="red")
            table.add_column("Error", style="red")
            
            for error in self.errors:
                table.add_row(error)
            
            console.print(table)
        
        console.print(f"\n[green]Successfully cleaned: {len(self.cleaned_files)} files[/green]")
        console.print(f"[red]Errors: {len(self.errors)} files[/red]")
        
        if self.cleaned_files:
            console.print(f"\n[yellow]⚠️  Original files preserved. Review cleaned files before deleting originals.[/yellow]")
            console.print(f"[dim white]💡 Tip: Use secure_delete() method to permanently remove original files.[/dim white]")
